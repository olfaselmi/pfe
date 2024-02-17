
# Dependencies
ConstructionError = require '../../src/ConstructionError'
{assert} = require 'chai'
testErrorClass = require '../helper/testErrorClass'

testErrorClass 'ConstructionError', ConstructionError, 'Error', Error
