
# Dependencies
{assert} = require 'chai'
DirectoryNotFoundError = require '../../src/DirectoryNotFoundError'
IOError = require '../../src/IOError'
testErrorClass = require '../helper/testErrorClass'

testErrorClass 'DirectoryNotFoundError', DirectoryNotFoundError, 'IOError', IOError
