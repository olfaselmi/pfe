
# Dependencies
ArgumentError = require './ArgumentError'

#>
# Argument Missing Error
# ======================
#
# Throw when a required argument is `undefined`
# or `null`.
#
class ArgumentMissingError extends ArgumentError

  # Class constructor
  constructor: (@message = 'Missing argument') ->

# Exports
module.exports = ArgumentMissingError
