# Compass Group PGSS Payslip Retriever
This is a Python script that retrieves your pay slips from Compass Group's PGSS
website and sends to your email. I wrote this script so I don't have to log onto
the stupid site every time I want to get my pay slips. What a stupid way to do
things.

I could've just filed an OFI to tell them to just email all the pay slips just
like any other normal companies do. Yup, that's gonna work because Compass Group
is more than capable of doing that.

![Snap image: "Don't do anything that might damage the reputation of Compass
Group"](/docs/snap_policy-rep.png)

Well, sack me then.

## Usage
```sh
python3 -m pgssret -f <config>
```
Where `<config>` is the path to the yaml configuration file. The sample is
located at [/docs/configs/sample.yaml](/docs/configs/sample.yaml).

## Setup
### Installation
Install the module using PIP.

```sh
pip install pgssret
```

### Configuration and Cache Setup
The config format is pretty self-explanatory. I copied and pasted into this doc
below for reference.

```yaml
pgss-ret:
  auth:
    username: USERNAME
    password: PASSWORD
  dir:
    cache: cache
    tmp: tmp
  limits:
    eml-size: 5242880 # 5 MiB
    nb-attachments: 20
  # Initial start up behaviour
  #   0: Attach only one latest pay slip only (recommended)
  #   1: Don't email. Pay slips will be sent on the subsequent launches
  #   2: Email all the pay slips obtainable. A large quantities of pay slips
  #      will be sent in multiple mails
  init-mode: 0
  post:
    subject: Pay Slip from Compass Group
    body: See attached.
    backend: smtplib
    params:
      proto: smtp # or 'smtps' or 'lmtp'
      # from: from@example.com
      # Allow use of unencrypted session. Set to true if using localhost
      # allow-plaintext: false
      # host: smtp.example.com
      # port:
      # tlscert:
      # tlskey:
      # cred: # smtp auth credentials
      #   username:
      #   password:
    recipients:
      # - person@example.com
```

You won't have to worry about cache and tmp dirs as long as you set the working
directory of the process correctly. I recommend preparing following paths for
the working directory of the module.

* Linux
  * `~/.cache/pgssret` for tmp and cache
  * `~/.config/pgssret` for the config
* Windows: `%appdata%\pgssret` for everything

Or you can use arbitrary directories on your machine and set them using absolute
paths.

Copy the sample config to a new location. Rename it to `pgssret.yaml` and edit
it. All you will have to change should be the username and password you use to
log onto the website. Then test the config by launching the module.

```sh
# Linux
cd ~/.cache/pgssret
python3 -m pgssret -f ~/.config/pgssret/pgssret.yaml
```
```pwsh
# Windows (Powershell or cmd)
cd %appdata%\pgssret
python3 -m pgssret -f %appdata%\pgssret\pgssret.yaml
```

If you mess up, debug the config and delete the cache file(named as
YOUR_EMPLOYEE_NUMBER.json) before relaunching the module. If you manage to get
the module to send an email successfully and you've confirmed that the email
has reached the inbox, you can move onto setting a scheduled task.

### Schedule Module Launch
On Linux, use crond or a Systemd timer to have the module poll your pay slips
periodically.

Run `crontab -e` to edit the user crontab like so.

```crontab
# To get error reports in the event of failure.
#MAILTO=

# Run pgssret every day at noon. Redirect STDOUT to the null device to get
# reports on errors only.
00 12 *  *  * cd ~/.cache/pgssret && python3 -m pgssret -f ~/.config/pgssret/pgssret.yaml > /dev/null
```

And make sure crond is running and you're good to go! Forget that you did all
this and let your computer get the pay slips for you from now on.

Another options is to make the machine run the module every time it boots up by
making a "oneshot" Systemd service or dropping a shell script in rc.d.

On Windows, Task Scheduler can do the trick.

![Task Scheduler dialog "General" tab](sched_prop-general.png)

![Task Scheduler dialog "Trigger" tab](sched_prop-trigger.png)

![Task Scheduler dialog "Action" tab](sched_prop-action.png)

![Task Scheduler dialog "Settings" tab](sched_prop-settings.png)

### Gmail Example
If you plan to use an external SMTP rather than a local one and set up a mail
filter on your email service[^1], here's the example using Gmail SMTP. You will
need to create an [App
Password](https://support.google.com/accounts/answer/185833) for the module.

```yaml
# ...
    params:
      proto: smtps
      from: you@gmail.com
      host: smtp.gmail.com
      cred:
        username: you@gmail.com
        password: THE_APP_PASSWORD
    recipients:
	  - you@gmail.com
```

[^1]: which is reasonable considering the fact that SMTP daemon implementations
      are quite heavy and it's tedious to set up a mail filter so that the mails
      sent from your local machine are not marked as spam
