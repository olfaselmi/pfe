
# Dependencies
ArgumentError = require '../../src/ArgumentError'
ArgumentRangeError = require '../../src/ArgumentRangeError'
{assert} = require 'chai'
testErrorClass = require '../helper/testErrorClass'

testErrorClass 'ArgumentRangeError', ArgumentRangeError, 'ArgumentError', ArgumentError
