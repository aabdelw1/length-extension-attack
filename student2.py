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

    #
    # The following is all purely sample code to familiarize yourself with some
    # of the available functions and methods. YOU CAN DELETE IT ALL.
    #
    forgery = message + injection

    # you can make queries to the oracle
    tag = oracle.query(message)

    # craft new message/tag based on those queries
    hasher = crypto.Sha1()
    hasher.update(forgery + tag)
    new_tag = hasher.hexdigest()
    hasher.clear()

    # convert easily between bytes and strings
    assert crypto.b2s(crypto.s2b(message)) == message
    assert crypto.s2b(crypto.b2s(b"cs6260")) == b"cs6260"

    # use sha1 internals directly:
    # hasher.sha1()
    # hasher.pad_message()
    # hasher.create_padding()
    manual_tag = hasher.sha1(crypto.s2b(forgery + tag),
                             extra_length=0, initial_state=None)
    assert new_tag == manual_tag

    # check the validity of novel tags
    if oracle.verify(message, tag):
        pass

    return forgery, oracle.query(forgery)


# if __name__ == '__main__':
message = "Hi there! We hope you have fun."
uid = "npavlovsky3"
main(message, uid)