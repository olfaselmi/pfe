
# Dependencies
ArgumentError = require '../../src/ArgumentError'
{assert} = require 'chai'
testErrorClass = require '../helper/testErrorClass'

testErrorClass 'ArgumentError', ArgumentError, 'Error', Error
