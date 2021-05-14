#!/usr/bin/env python3
# DO NOT CHANGE THIS FILE.
import random
import string
import argparse

import oracle, crypto
import student


# If you want to try out other messages, do it separately.
# This is the message you must inject your username into.
MESSAGE = "Hi there! We hope you have fun."


parser = argparse.ArgumentParser(description="Grades the length extension attack on SHA1.")
parser.add_argument("username", help="your GT username (e.g. djoyner3)")
args = parser.parse_args()


# Create a random secret.
print("Generating random secret... ", end="")
with open("secret.txt", "wb") as f:
    secret = "".join([
        random.choice(string.ascii_letters)
        for _ in range(64)
    ])

    f.write(crypto.s2b(secret))
print("done.")

print("=============== Student Output ===============")
message, tag = student.main(MESSAGE, args.username)
print("===================== END ====================")

if oracle.check(message, tag):
    print("\nTEST PASSED")
    print("Good job!")

    if args.username in message and MESSAGE in message:
        print("Unless you did something really shady (like hardcode a secret, "
              "modify the oracle, etc.), you successfully executed a length "
              "extension attack against SHA1!")
    else:
        print("It looks like you successfully forged a message, but didn't "
              "include your GT username or the original message in your forgery.")

else:
    print("\nTEST FAILED")
    print("Unfortunately, the (message, tag) pair you returned doesn't pass "
          "the oracle's integrity check. Try again!")
