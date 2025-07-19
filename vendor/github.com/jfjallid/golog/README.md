# GoLog

Package golog or "GoLog" serves as a wrapper around the default log package to
implement logging levels:
  - Critical
  - Error
  - Warning
  - Notice
  - Info
  - Debug

Where a configured level of Error would only print messages of type Error and
Critical, while a level of Debug would print all log messages.

The package defines a type MyLogger, with methods for formatting output, same
as the log package, and it also has a predefined 'standard' logger with
associated logging functions that can be used without creating a custom logger.
This standard logger has a predefined loglevel of Notice which means that any
logs created by Info or Debug functions will be discarded.
However, note that the standard logger's settings including loglevel can be
updated with the Set functions same as the custom loggers.

The idea with this library is to use the standard logger when a shared logger
is desired in the whole project across all packages where the main function
configures the settings that should apply to everyone. If custom log settings
is desired per package, create custom logger objects with the function New(...)
