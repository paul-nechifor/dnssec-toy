# This repository has been moved to [gitlab.com/paul-nechifor/dnssec-toy](http://gitlab.com/paul-nechifor/dnssec-toy).

Old readme:

# DNSSEC Toy

A DNSSEC server and resolver implementation.

![DNSSEC Toy cover image.](screenshot.png)

This project includes:

* an authoritative server;
* an iterative resolver;
* a keypair generator tool;
* a zone signing tool;
* and an example tree for testing.

This was one of my homeworks for the [Information Security][is] course.

## Build

Run:

    mvn package

## Example

Go to `example`:

    cd example

Look at the example tree:

    cat tree

You have to start multiple authoritative servers and a resolver. You can install
`tmux` and use the configuration file to start everyting:

    tmux -f tmux.conf attach

Type a query in the resolver. For example to get the IP address for
`paul.pers.ro` type `paul.pers.ro. A`.

## License

MIT

[is]: http://www.infoiasi.ro/bin/Programs/CS3102_11
