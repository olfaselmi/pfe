
# Dependencies
{assert} = require 'chai'
IOError = require '../../src/IOError'
FileNotFoundError = require '../../src/FileNotFoundError'
testErrorClass = require '../helper/testErrorClass'

testErrorClass 'FileNotFoundError', FileNotFoundError, 'IOError', IOError
