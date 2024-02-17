
# Dependencies
IOError = require './IOError'

#>
# File Not Found Error
# ====================
#
# Throw when a requested file is not found.
#
class FileNotFoundError extends IOError

  # Class constructor
  constructor: (@message = 'File not found') ->

# Exports
module.exports = FileNotFoundError
