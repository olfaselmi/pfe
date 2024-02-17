
# Dependencies
ArgumentError = require './ArgumentError'

#>
# Argument Out Of Range Error
# ===========================
#
# Throw when an argument value is out of the
# expected range.
#
# Example:
#
#     if id < 1
#       throw new ArgumentOutOfRangeError()
#
class ArgumentOutOfRangeError extends ArgumentError

  # Class constructor
  constructor: (@message = 'Argument out of range') ->

# Exports
module.exports = ArgumentOutOfRangeError
