
#>
# Argument Error
# ==============
#
# Throw when an argument is set to an unexpected
# or incorrect value.
#
class ArgumentError extends Error

  # Class constructor
  constructor: (@message = 'Invalid argument') ->

# Exports
module.exports = ArgumentError
