
#>
# Construction Error
# ==================
#
# Throw when a constructor function is called
# without the `new` keyword.
#
class ConstructionError extends Error

  # Class constructor
  constructor: (@message = 'Bad construction, missing `new` keyword') ->

# Exports
module.exports = ConstructionError
