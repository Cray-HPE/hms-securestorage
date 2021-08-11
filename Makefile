NAME ?= hms-securestorage 
VERSION ?= $(shell cat .version)

all : unittest coverage

unittest: 
		./runUnitTest.sh

coverage:
		./runCoverage.sh	
