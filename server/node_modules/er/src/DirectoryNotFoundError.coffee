
# Dependencies
IOError = require './IOError'

#>
# Directory Not Found Error
# =========================
#
# Throw when a requested directory is not found.
#
class DirectoryNotFoundError extends IOError

  # Class constructor
  constructor: (@message = 'Directory not found') ->

# Exports
module.exports = DirectoryNotFoundError
