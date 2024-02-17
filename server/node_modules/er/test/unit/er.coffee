
# Dependencies
{assert} = require 'chai'

# All error classes
errorClasses = [
  'ArgumentError'
  'ArgumentMissingError'
  'ArgumentRangeError'
  'ArgumentTypeError'
  'ConstructionError'
  'DirectoryNotFoundError'
  'FileNotFoundError'
  'IOError'
]

# Tests
suite 'er module', ->
  module = require '../../src/er'

  test 'should be an object', ->
    assert.isObject module

  # Test for each error class
  for errorClass in errorClasses
    do (errorClass) ->
    
      test "should have a #{errorClass} property", ->
        assert.isDefined module[errorClass]

      test "#{errorClass} property should be equal to the #{errorClass} module", ->
        assert.strictEqual module[errorClass], require("../../src/#{errorClass}")
