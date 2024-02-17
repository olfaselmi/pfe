
#>
# IO Error
# ========
#
# Throw when a filesystem operation fails.
#
class IOError extends Error

  # Class constructor
  constructor: (@message = 'IO Error') ->

# Exports
module.exports = IOError
