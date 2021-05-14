#!/usr/bin/env python3
#Ammmar's Implementation

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

    #
    # The following is all purely sample code to familiarize yourself with some
    # of the available functions and methods. YOU CAN DELETE IT ALL.
    #

    inital_state = initialize(message)
    
    message_bytes = crypto.s2b(message)
    message_padded = crypto.Sha1.pad_message(message_bytes, 512)

    injection_bytes = crypto.s2b(injection)
    forgery = message_padded + injection_bytes
    forgery_string = crypto.b2s(forgery)

    sha = crypto.Sha1()
    message_length = (len(message_padded) * 8) + 512

    updated_tag = sha.sha1(injection_bytes, message_length, initial_state=inital_state)
    # sanityCheck(forgery_string, updated_tag)

    return forgery_string, updated_tag


def initialize(message):
    tag = oracle.query(message)
    tag_bytes = crypto.s2b(tag)

    tis = int(tag_bytes, 16)
    a = tis >> 128
    b = (tis >> 96) & 0xffffffff
    c = (tis >> 64) & 0xffffffff
    d = (tis >> 32) & 0xffffffff
    e = tis & 0xffffffff

    return [a,b,c,d,e]

def sanityCheck(forgery, tag):
    if oracle.check(forgery, tag):
      print("message BROKEDN")
    else:
      print("you failed")

# if __name__ == '__main__':
#   message = "Hi there! We hope you have fun."
#   uid = "aabdelwahed3"
#   main(message, uid)

