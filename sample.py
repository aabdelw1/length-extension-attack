#!/usr/bin/env python3

# Feel free to import anything you need from the standard library.
import oracle
import crypto

def main(message, injection):
    """ Your goal is to bypass the oracle's integrity check.

    This will break UF-CMA security of the scheme and demonstrate a length
    extension attack on the underlying SHA1 hash function, which relies on the
    Merkle-Damgard construction internally.

    Specifically, you must somehow craft a message that includes the given
    parameter WITHIN the default message AND find a valid tag for it WITHOUT
    querying the oracle.

    Your attack should be able to inject any message you want, but we want you
    to include your GT username specifically.
    """
    print("forging message that includes %s within %s" % (injection, message))

    #
    # TODO: Find a way to break UF-CMA security of the scheme.
    #
    # Step #1: we calculate the message we want to forge
    appending_for_forgery = " " + injection
    print("The \'appending_for_forgery\' string we want to include = \"{0}\"\n".format(appending_for_forgery))

    # Step #2: we need to get the the SHA-1 hash of the original message
    # into which we are going to inject the "injection" string
    print("First, we get the original message's SHA-1 Hash")
    print()
    original_message_hash_string = oracle.query(message)
    print()

    print("DEBUG: the original message hash string is: {0}\n".format(original_message_hash_string))

    # Step #3: we need to create a new "initial_state" based on the original message
    #          This new initial state is a list of 5 32-bit values which allows the
    #          attacker to "pick up where we left off" and perform the length extension attack
    new_state = calculate_length_extension_attack_continuation_state(original_message_hash_string)
    print("The new_state is the following list of 5 32-bit values: {0}\n".format(new_state))

    # Step #4: We now have the message that we want to forge being "Key || message || appending_for_forgery"
    #          We know the length of the message and the appending_for_forgery but don't know the length of the key
    #          In this extension attack, we continue from here henceforth by determining the length of the Key.
    #          Doing so is necessary because per SHA-1's RFC section 4 [https://tools.ietf.org/html/rfc3174#section-4]
    #          We have to pad the message depending on its original length.
    #          Because we know the max key size, we will brute force our way through
    MAX_SIZE_KEY_IN_BYTES = 100
    for key_length_in_bytes in range(0, MAX_SIZE_KEY_IN_BYTES + 1):
        # We now brute force our way through different key length possibilities and see if we can FORGE THE MESSAGE!
        print("DEBUG: key length in bytes is = {0}".format(key_length_in_bytes))
        forged_message, forged_tag = create_forged_message_candidate(new_state, message, appending_for_forgery, key_length_in_bytes)

        if oracle.verify(forged_message, forged_tag):
            print("We have cracked the puzzle!")
            print("\tThe secret key's length in bytes is: {0}".format(key_length_in_bytes))
            print("\tThe forged message is: {0}".format(forged_message))
            print("\tThe forged tag is: {0}".format(forged_tag))
        else:
            print("\tDEBUG: The forged_tag was not successfully verified against the forged_message for key_length {0}".format(key_length_in_bytes))

    #------------------------------------------------------------------------------------------------
    print()
    print()
    print("DONE WITH THE PROGRAM HERE! If there was no cracking of the puzzle by this point, something went wrong")

    # TODO: RETURN THE FOLLOWING STUFF ONCE WE ARE DONE
    #return forgery, oracle.query(forgery)

###############################################################################
#
# We are using a custom implementation of the SHA-1 hash function
# in the crypto.py file. This custom implementation receives an
# array of 5 32-bit values as an "initial_state" parameter.
# In the SHA-1 RFC, the "initial_state" parameter is also known as the "H's"
# Source for the name of the H's: https://tools.ietf.org/html/rfc3174#section-6.1
#
# This function basically calculates a specially-pre-configured initial_state
# parameter so that we can "pick up" where we left off and append data of any length
# to the original message
def calculate_length_extension_attack_continuation_state(orig_hash_str):
    # The new initial_state array from which we are "continuing" after the original data is read
    # has 5 32-bit values. The hash is of the original message to which we want to append data of any length
    #
    # We now calculate the new state array's members
    length_of_state_block = len(orig_hash_str)//5
    new_state_block_in_strings = [orig_hash_str[i:i+length_of_state_block] for i in range(0, len(orig_hash_str), length_of_state_block)]
    #
    # We now extract the new state block represented in an array of integer representation of the 5 32-bit values
    new_state_block_in_hex = list( map(lambda string_hex_num: int(string_hex_num, 16), new_state_block_in_strings))
    return new_state_block_in_hex

###############################################################################
#
# Creates a candidate for a forged message in brute force
def create_forged_message_candidate(fixed_state_array, original_message, message_to_append_in_the_forgery, length_of_key_in_bytes):
    # We perform a linear extension attack for a specified key length to see if it works
    print("\t\tDEBUG: IN CREATE_FORGED_MESSAGE_CANDIDATE")
    print()
    print("\t\tProvided parameters: ")
    print("\t\t\tFixed State Array: {0}".format(fixed_state_array))
    print("\t\t\tOriginal message: {0}".format(original_message))
    print("\t\t\tMessage to append in the forgery: \'{0}\'".format(message_to_append_in_the_forgery))
    print("\t\t\tLength of the key in bytes: {0}".format(length_of_key_in_bytes))
    print()
    print()

    #------------------------------------------------------------------------
    start_of_forged_message = crypto.s2b("B" * length_of_key_in_bytes + original_message + message_to_append_in_the_forgery)
    forged_message = crypto.Sha1.pad_message(start_of_forged_message)
    print("\t\tDEBUG: the start of the forged message = {0}".format(forged_message))
    print("\t\tDEBUG: type of forged_message = {0}".format(type(forged_message)))

    # OK we need to remove our key from the forged message here because it is not the correct key ANYWAYS!
    print("\t\tDEBUG: testing the byte slicing from the forged message to remove the fake key from the beginning!")
    forged_message = forged_message[length_of_key_in_bytes:]
    print("\t\t\tDEBUG: the result is: {0}".format(forged_message))

    # OK, now we call the SHA-1 function with the fixed state and the extra message information we have to forge the final result
    hasher = crypto.Sha1()
    hasher.update(forged_message)

    print()
    print("\t\tDEBUG: the extra_length parameter = {0}".format((length_of_key_in_bytes + len(forged_message)) * 8))
    new_tag = hasher.hexdigest((length_of_key_in_bytes + len(forged_message)) * 8, fixed_state_array) # FIX THIS LINE

    print()
    print("\t\tThe result of the new Sha-1 invocation is as follows:")
    print("\t\t\tThe new forged_message = {0}".format(forged_message))
    print("\t\t\tThe new tag = {0}".format(new_tag))
    print()
    return forged_message, new_tag




###############################################################################
# TODO: REMOVE THE FOLLOWING MAIN FUNCTION INVOCATION WHEN WE ARE COMPLETELY SURE ATTACK WORKS AND WANT TO TEST IN GRADER.py file
if __name__=="__main__":
    main("Hi there! We hope you have fun.", "npavlovsky3")