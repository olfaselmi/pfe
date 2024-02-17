
# Dependencies
ArgumentError = require '../../src/ArgumentError'
ArgumentTypeError = require '../../src/ArgumentTypeError'
{assert} = require 'chai'
testErrorClass = require '../helper/testErrorClass'

testErrorClass 'ArgumentTypeError', ArgumentTypeError, 'ArgumentError', ArgumentError
