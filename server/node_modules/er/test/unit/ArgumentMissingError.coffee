
# Dependencies
ArgumentError = require '../../src/ArgumentError'
ArgumentMissingError = require '../../src/ArgumentMissingError'
{assert} = require 'chai'
testErrorClass = require '../helper/testErrorClass'

testErrorClass 'ArgumentMissingError', ArgumentMissingError, 'ArgumentError', ArgumentError
