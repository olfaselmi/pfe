
# Dependencies
{assert} = require 'chai'
IOError = require '../../src/IOError'
testErrorClass = require '../helper/testErrorClass'

testErrorClass 'IOError', IOError, 'Error', Error
