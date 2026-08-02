# GoLog

Package golog or "GoLog" serves as a wrapper around the default log package to
implement logging levels:
  - Critical
  - Error
  - Warning
  - Notice
  - Info
  - Debug
  - Trace

Where a configured level of Error would only print messages of type Error and
Critical, while a level of Trace would print all log messages.

The package defines a type MyLogger, with methods for formatting output, same
as the log package, and it also has a predefined 'standard' logger with
associated logging functions that can be used without creating a custom logger.
This standard logger has a predefined loglevel of Notice which means that any
logs created by Info, Debug, or Trace functions will be discarded.
However, note that the standard logger's settings including loglevel can be
updated with the Set functions same as the custom loggers.

The idea with this library is to use the standard logger when a shared logger
is desired in the whole project across all packages where the main function
configures the settings that should apply to everyone. If custom log settings
is desired per package, create custom logger objects with the function New(...)

## Child loggers (With)

`(*MyLogger).With(prefix)` returns a detached child logger that prepends a
prefix to every message, after the parent's display name:

```go
base := golog.Get("smb/server")
conn := base.With("[192.0.2.7:49832]")
conn.Errorf("connection reset")
// => smb/server [192.0.2.7:49832] [Error] connection reset
```

The child copies the parent's level, flags, per-level flag overrides, prefix
and output destinations at the time of the call but owns fresh underlying
loggers, so later `SetFlags`/`SetOutput`/`SetLogLevel`/`SetLevelFlags` calls on
either side do not affect the other. Children are not registered in the package
logger registry (`Get`/`Set`/`Names`/`SetAll` neither see nor update them),
which makes them suited to short-lived per-connection or per-session context
such as a remote address.

## Per-level flags

`SetFlags` sets the log flags (`Ldate`, `Ltime`, `Lshortfile`, ...) shared by
all levels. A single level can override those flags with `SetLevelFlags`,
leaving the base flags untouched for every other level:

```go
lg := golog.Get("smb/server")
lg.SetLevelFlags(golog.LevelWarning, golog.LstdFlags|golog.Lshortfile)
```

By default `New` (and therefore `Get`) seeds `LevelDebug` and `LevelTrace` with
the base flags plus `Lshortfile`, so debug and trace messages record the file
and line that produced them while the other levels stay clean:

```
smb/server [Debug] conn.go:142: tree connect for IPC$
smb/server [Notice] client connected
```

Use `ClearLevelFlags(level)` to drop an override and inherit the base flags
again, and `LevelFlags(level)` to read the effective flags for a level. Each of
these has both a method form and a package-level form acting on the standard
logger.
