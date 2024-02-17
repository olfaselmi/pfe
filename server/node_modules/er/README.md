
# Er... #

A small set of custom error classes for Node.js.


## Installation ##

Just install with `npm install er` or add it to your
`package.json`.


## Usage ##

Er... is really easy to use, it's just a set of error classes!
All of the classes are available by requiring the 'er' module,
and they all extend `Error` so you can throw them :)

```js
// JavaScript
var FileNotFoundError = require('er').FileNotFoundError;
throw new FileNotFoundError('File secret-stuff.txt was not found');
```

```coffeescript
# CoffeeScript
{FileNotFoundError} = require 'er'
throw new FileNotFoundError 'File secret-stuff.txt was not found'
```

The `er` namespace has the following properties, each of which
is an error class:

**ArgumentError**  
Throw when an argument is set to an unexpected or incorrect
value.

**ArgumentMissingError** *extends ArgumentError*  
Throw when a required argument is `undefined` or `null`.

**ArgumentRangeError** *extends ArgumentError*  
Throw when an argument value is out of the expected range.

**ArgumentTypeError** *extends ArgumentError*  
Throw when an argument type is invalid.

**IOError**  
Throw when a filesystem operation fails.

**DirectoryNotFoundError** *extends IOError*  
Throw when a requested directory is not found.

**FileNotFoundError** *extends IOError*  
Throw when a requested file is not found.

**ConstructionError**  
Throw when a constructor function is called without the `new`
keyword.


## Development ##

In order to develop Er..., you'll need to install the following
npm modules globally like so:

    npm install -g coffee-script
    npm install -g jake

And then install development dependencies locally with:

    npm install

Once you have these dependencies, you will be able to run the
following commands:

`jake build`: Build JavaScript from the CoffeeScript source.

`jake lint`: Run CoffeeLint on the CoffeeScript source.

`jake test`: Run all unit tests.


## License ##

Dual licensed under the [MIT][mit] or [GPL Version 2][gpl]
licenses.


[bookbind]: http://github.com/rowanmanning/bookbind
[jake]: http://github.com/mde/jake
[mit]: http://opensource.org/licenses/mit-license.php
[gpl]: http://opensource.org/licenses/gpl-2.0.php
