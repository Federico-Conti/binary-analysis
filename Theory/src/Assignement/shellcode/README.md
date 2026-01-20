# Shellcoding exercises

## Preliminaries

For these exercises, the following ones and the exam, you will need to use our VPN. If you have not checked it yet, please read
the [VPN instructions](VPN.md) carefully, and verify that you can connect.

## Your task

In this assignment, you'll practice your skills in shellcoding and basic
exploitation. We provide the executable programs running on the remote server,
so you can reverse them and try your exploits locally. However, the flags
are only present in the remote services, so your exploits must work
remotely too to capture the flags.

The challenges of this assignment have increasing difficulty:

- **BOF 101** is an introductory challenge to buffer overflows. It is
  very simple. After having studied the corresponding topic, you should not have any problems in solving it.
- **Smallcode x64** and **No syscalls x86** are a bit harder,
  but you should be able to solve them with some effort.
- The last two challenges are more, let's say, *interesting*. They are definitely optional, don't worry if you can't solve them (and be very proud if you can :wink:).

So, start from the first one and proceed in order; solve as many challenges as possible. Then,

- write a report describing how you tackled/solved each challenge;
- provide your exploit scripts (and possibly other files, if helpful).

In your report, specify which tools you used and how. If you like, you can include screenshots to describe your workflow better.

Your report should be written in English.
Please avoid MS/Open/Libre-office formats: a plain ASCII, markdown or a PDF are fine.
Add your report to your repository, as usual, to submit your work.

Finally, remember that you need to be connected to our [VPN](VPN.md)
to reach the services.

## Service details

All services are listening on IP address `192.168.20.1`. However, each of you needs to connect to a different port, depending on your *base-port* as specified in your VPN configuration file.

**IMPORTANT**: *brute-forcing is never required* to solve these challenges.
Please **do not perform a Denial-of-Service attack** to our poor server.

### BOF demo - port: (*base-port*+1)

[bof-demo](bof-demo) is simply the running example used during lectures.
  
MD5: 5083ebaddbe1eaf439667edd1c631229

### BOF 101 - port: (*base-port*+2)

[BOF-101](bof101_x86) is an introductory challenge to buffer overflows.
Your goal is to spawn a shell and read the file `flag.txt`.

Being your first shellcoding challenge, we provide its [simplified source code](bof101.c) too. Don't get used to it, though ;)

Please note that the actual sources are a bit more complex than this, since they contain some additional code to pretty-print the stack addresses/contents.
So, this source allows you to understand better what is happening. However, do not compile it (you would get a *different* binary).

MD5: 6819dda6e93e1e193a72bb2015fde0a3

### Smallcode x64 - port: (*base-port*+3)

Tongue-in-cheek description:
> Don't be fooled by my name: I'm a *great* code-runner ;-) ...
> though I can only run a small amount of code each time.

MD5: 4e722b224f5f31e6e4b7427a6df26719

### No syscalls x86 - port: (*base-port*+4)

Tongue-in-cheek description:
> This challenge uses a sophisticated (yeah, right) sandbox technology to run any
> x86 shellcode, up to 42 bytes, safely.
>
> The only catch is that the shellcode should not contain system calls.
> So, our sandbox is impenetrable!
>
> However, we left a `flag.txt` on our server, just in case.

MD5: 611c26ae1351a90f351c917b3454c814

### Blockchain - port: (*base-port*+5)

Tongue-in-cheek description:
> This is a blockchain (not *that* blockchain) builder.
> That is, you provide a series of 5-byte blocks, and we join them together,
> then run the resulting chain.

MD5: 27bbc1aeee7c612986b28288c35b0fea

### Going-up - port: (*base-port*+6)

In this challenge you need to provide a sequence of increasing integers, that will then be run (as machine code, obviously). That's devious, isn't it?

MD5: 51cd916bd392385b8a573bf548b27c48
