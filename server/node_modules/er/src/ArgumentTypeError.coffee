
# Dependencies
ArgumentError = require './ArgumentError'

#>
# Argument Type Error
# ===================
#
# Throw when an argument type is invalid.
#
class ArgumentTypeError extends ArgumentError

  # Class constructor
  constructor: (@message = 'Argument type invalid') ->

# Exports
module.exports = ArgumentTypeError
