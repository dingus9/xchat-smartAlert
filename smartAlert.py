import xchat
import gntp.notifier
import os
import platform
import psutil
import re
import time

__module_name__ = "smartAlert"
__module_version__ = "1.1"
__module_description__ = "Customize XChat Alerting + Logging"


# Define all match rules and result callbacks here.
class Rules(dict):

    def __init__(self):
        self.rules = ({'users': ['nebnotify'],
                      'str': 'HMDB ETL',
                      'bool': 'and',
                      'callback': self._hosting_matrix_etl,
                      'eat': xchat.EAT_NONE},
                      {'users': ['meow_bot'],
                      'callback': self._maas_alert_bot},
                      {'channels': ['#ubuntu', '#puppet', '#asd'],
                      'callback': self._anymessage},
                      )

        # used for alert timout queues in callback methods
        self.alerts = {'maas_issue': {'timeout': 120},
                       'nicks_user': {'timeout': 30}}

    def eat(self, rule):
        if 'eat' in self.rules[rule].keys():
            return self.rules[rule]['eat']
        else:
            return 'none'

    def filter_match(self, user, channel, message):
        retval = False
        for rule in self.rules:
            rslt = {}
            for name, test in rule.iteritems():
                # Is one of users
                if name == 'users':
                    rslt.setdefault('users', False)
                    for usr in test:
                        if xchat.nickcmp(usr, user) == 0 or usr == '*':
                            rslt['users'] = True
                            continue
                elif name == 'str':
                    if message.find(test) > 0:
                        rslt['str'] = True
                    else:
                        rslt['str'] = False
                elif name == 'channel':
                    if xchat.nickcmp(channel, test) == 0:
                        rslt['channel'] = True
                    else:
                        rslt['channel'] = False

            if 'bool' in rule:
                if rule['bool'] == 'or' and any(rslt.values()):
                    print rule
                    retval = rule
            elif all(rslt.values()):
                retval = rule

        if retval:
            return retval
        else:
            return None

    def _test(self, scope, user, channel, string):
        if self._alert_timeout('nicks_user'):
            message = string
            title = "You"
            return {'notif': 'Notify', 'message': message, 'title': title}

    def _hosting_matrix_etl(self, scope, user, channel, string):
        reg = re.compile('(.*) - (SUCCESS|INFO|ALERT|.*) - - HMDB ETL \((.*)\) (.*)')
        match = reg.match(string)
        groups = match.groups()
        result = {'notif': 'Cron', 'message': groups[2].upper() + "->ETL: " +
                  groups[1] + ' - ' + groups[3],
                  'title': 'something'}
        return result

    def _maas_alert_bot(self, scope, user, channel, string):
        if self._alert_timeout('maas_issue'):
            message = string
            title = "MaaS Alert"
            return {'notif': 'Alert', 'message': message, 'title': title}
        else:
            return False

    def _anymessage(self, scope, user, channel, string):
        result = None
        if self._alert_timeout('nicks_user'):
            result = channel + " >> " + user + ': ' + string
        return result

    # Checks for timeout, returns true if timeout met or false if timeout still in effect.
    # Name string, an key of self.alerts "[name]", may be shared between callbacks if desired.
    def _alert_timeout(self, name):
        now = int(time.time())
        if 'timeout' in self.alerts[name].keys():
            timeout = self.alerts[name]['timeout']
            seen = self.alerts[name].setdefault('seen', now)
            if now > seen + timeout:
                self.alerts[name]['seen'] = now
                return True
            else:
                return False


class SmartAlert():
    def __init__(self, rules):
        print self.__class__.__name__ + ": Loading" + sufix
        pid = psutil.Process(os.getpid())
        self.appname = pid.name
        self.rules = rules
        self.alerters = []
        self.os = platform.system()
        if self.os == 'Darwin':  # Handle special osx container setup
            self.icon = os.getenv("HOME") + "/xchat.png"
        else:
            self.icon = None

        # Setup Alerting Environment
        self.notifs = ('Message', 'Alert', 'Notify')

        # Register growl alerter
        self.addAlerter(Growlify(self.notifs, self.appname, self.icon))

    def addAlerter(self, alerter):
        print "Registering Alerter: " + alerter.__class__.__name__ + "..."
        self.alerters.append(alerter)
        alerter.alert(self.notifs[0], self.__class__.__name__, 'Initializing alerter')

    # Message is the main callback for a generic message event.
    # it assumes no command was issued so it should only be bound to a message even type.
    def message(self, word, word_eol, userdata):
        # user and message detection is arbitrary to xchat... might want to look at
        # a more dynamic IRC formmating method for determining the message user and
        # other attributes.
        if len(word) == 2:
            user = word[0]
            message = word[1]
        elif len(word) == 3 and word[2] == '@':
            user = word[0]
            message = word[1]
        channel = xchat.get_info('channel')
        scope = xchat.get_info('server')

        notify = None
        # Match on one rule for now, later we might support multi matches for multi dests
        # or what ever. But right now I'm only needing growl and one type of match.
        matched = self.rules.filter_match(user, channel, message)
        if matched:
            if 'callback' in matched:
                notify = matched['callback'](scope, user, channel, message)
                if not type(notify) == dict and notify is not None:
                    notify = {"message": notify, 'title': 'Misc', 'notif': 'Notify'}
            else:
                #simulated response object... Used if I don't care to callback
                notify = {'message': message, 'title': 'Misc', 'notif': 'Notify'}

        if notify:
            self.alert(**notify)

    # notif dict {'notif', 'message', 'title'}
    def alert(self, **args):
        for alerter in self.alerters:
            alerter.alert(args['notif'], args['title'], args['message'])

    # Callback for xchat.unload()
    def unload(self, userdata):
        print self.__class__.__name__ + ": Unloading" + sufix


class Growlify():

    #send tuple of notifs looking like ["Nice Notifs Name","Other Nice Name"]
    def __init__(self, notifs, appname, icon):
        image = open(icon, 'rb').read()
        self.appname = appname
        self.notifs = notifs
        self.icon = icon
        self.growl = gntp.notifier.GrowlNotifier(
            applicationName=appname,
            notifications=notifs,
            defaultNotifications=notifs[0],
            applicationIcon=image)#self.icon.replace(' ', '\ '),)
            # hostname = "computer.example.com", # Defaults to localhost
            # password = "abc123" # Defaults to a blank password
        self.growl.register()

    def alert(self, notif, title, message, icon=None):
        if icon:
            icon = open(self.icon, 'rb').read()
        self.growl.notify(
            noteType=notif,
            title=title,
            description=message,
            sticky=False,
            icon=icon,
            priority=1,)

# Initialize Alert Object
sufix = '...'
print __module_name__ + ": Initializing" + sufix
rules = Rules()
alerts = SmartAlert(rules)

# Hook Print Events
print __module_name__ + ": Loading hooks" + sufix

# Possible Event binds:
# Your Message
# Message Send -- when sending a priv message
# Private Message
# Private Message to Dialog
# Generic Message -- doesn't seem to work -- probably only at server level
# Channel Message
xchat.hook_print('Channel Message', alerts.message, userdata=None, priority=xchat.PRI_NORM)
xchat.hook_unload(alerts.unload)
