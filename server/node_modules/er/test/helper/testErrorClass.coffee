
# Dependencies
{assert} = require 'chai'

# Test a custom error class
module.exports = (errorName, errorClass, extendsName, extendsClass) ->

  suite "#{errorName} module", ->
    Module = errorClass

    test 'should be a function', ->
      assert.isFunction Module

    suite 'instance with no message set', ->
      instance = null

      setup ->
        instance = new Module

      teardown ->
        instance = null

      test "should extend #{extendsName}", ->
        assert.instanceOf instance, extendsClass

      test 'message property should be a string', ->
        assert.isString instance.message

      test 'message property should be an unempty string', ->
        assert.notStrictEqual instance.message, ''

    suite 'instance with a message set', ->
      instance = null

      setup ->
        instance = new Module 'foo'

      teardown ->
        instance = null

      test 'message property should be a string', ->
        assert.isString instance.message

      test 'message property should be equal to the message argument passed into the constructor', ->
        assert.strictEqual instance.message, 'foo'
