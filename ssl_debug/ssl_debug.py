#!/usr/bin/env python

"""ssl_debug

Usage:
  ssl_debug.py info <host> <port>

Options:
  -h --help                   Show this screen
  --version                   Show version

"""

import socket
from OpenSSL import SSL, crypto
import hashlib


def verify_cb(conn, cert, errnum, depth, ok):
	return True


def describe_cert(cert):
	print "      Subject: {}".format(cert_component_string(cert.get_subject().get_components()))
	print "       Issuer: {}".format(cert_component_string(cert.get_issuer().get_components()))
	print "    Signature: {}".format(cert.get_signature_algorithm())
	print "       Serial: {}".format(cert.get_serial_number())
	print " Key Strength: {}".format(cert.get_pubkey().bits())
#	print " Key Strength: {}".format( crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey()) )


def cert_component_string(components):
	output = []
	for component in components:
		output.append("=".join(component))
	return "/".join(output)

if __name__ == '__main__':
	from docopt import docopt

	arguments = docopt(__doc__, version='db 1.0')

	if arguments['info']:
		ctx = SSL.Context(SSL.SSLv23_METHOD)
		ctx.set_verify(SSL.VERIFY_NONE, verify_cb)
		ctx.set_verify_depth(9)

		sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
		sock.connect((arguments['<host>'], int(arguments['<port>'])))
		sock.send("HEAD / HTTP/1.0\n\n")

		cert = sock.get_peer_certificate()
		chain = sock.get_peer_cert_chain()

		print "[ Certificate Information ]:"
		describe_cert(cert)

		print "\n"

		print "[ Chain Information ]:"
		for c in chain:
			describe_cert(c)
			print ""
