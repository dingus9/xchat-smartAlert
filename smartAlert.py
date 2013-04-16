import xchat
import gntp.notifier
import os
import platform
import psutil
import re
import time

__module_name__ = "Smart Alerts"
__module_version__ = "1.0"
__module_description__ = "Customize XChat Alerting + Logging"


# Define all match rules and result callbacks here.
class Rules(dict):

    def __init__(self):
        self.rules = [{'users': ['nebnotify'],
                      'str': 'HMDB ETL',
                      'bool': 'and',
                      'callback': self._hosting_matrix_etl,
                      'eat':xchat.EAT_NONE},
                      {'users': ['meow_bot'],
                      'callback': self._maas_alert_bot}
                      ]

        self.alerts = {'maas_issue': {'timeout': 120}}

    def eat(self, rule):
        if 'eat' in self.rules[rule].keys():
            return self.rules[rule]['eat']
        else:
            return 'none'

    def filter_match(self, user, channel, message):
        for rule in self.rules:
            rslt = {}
            for name, test in rule.iteritems():
                # Is one of users
                if name == 'users':
                    rslt['users'] = False
                    for user in test:
                        if xchat.nickcmp(user, test) == 0:
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

            if 'bool' in self.rules:
                if rules['bool'] == 'or' and any(rslt.values()):
                    return rule
            elif all(rslt.values()):
                return rule
            else:
                return -1

    def _hosting_matrix_etl(self, context, user, channel, string):
        reg = re.compile('(.*) - (SUCCESS|INFO|ALERT|.*) - - HMDB ETL \((.*)\) (.*)')
        match = reg.match(string)
        groups = match.groups()
        result = {'notif': 'Cron', 'message': groups[2].upper() + "->ETL: " +
                  groups[1] + ' - ' + groups[3],
                  'title': 'something'}
        return result

    def _maas_alert_bot(self, context, user, channel, string):
        if self._alert_seen('maas_issue'):
            #format alert
            pass
        else:
            return False

    # Checks for timeout, returns true if timeout met or false if timeout still in effect.
    def _alert_seen(self, name):
        now = int(time.time())
        if 'timeout' in self.alerts[name].keys():
            timeout = self.alerts[name]['timeout']
            seen = self.alerts.get('seen', 0)
            if seen > 0 and now > seen + timeout:
                self.alerts[name]['seen'] = now
                return True
            else:
                return False
        else:
            self.alerts[name]['seen'] = now


class SmartAlert():
    def __init__(self, rules):
        print self.__class__.__name__ + ": Loading" + sufix
        pid = psutil.Process(os.getpid())
        self.appname = pid.name
        self.rules = rules
        self.alerters = []
        self.os = platform.system()
        if self.os == 'Darwin':
            #self.icon = os.path.abspath(os.path.dirname(pid.exe) +
            #                            '/../Resources/xchat.icns')
            self.icon = "/Users/will5324/Desktop/xchat.png"
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

    def message(self, word, word_eol, userdata):
        user = word[1]
        message = word_eol[2]
        channel = xchat.get_list('channel')
        context = channel.context
        matched = self.rules.filter_match(user, channel.channel, message)
        if matched > 0:
            if 'callback' in self.rules[matched].keys():
                notify = self.rules[matched]['callback'](context, user, channel, message)
            else:
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
        image = open('/Users/will5324/test.txt', 'r')
        #image = open(icon, 'r')

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

    def alert(self, notif, title, message):
        #image = open(self.icon, 'rb').read()
        print self.icon.replace(' ', '\ ')
        self.growl.notify(
            noteType=notif,
            title=title,
            description=message,
            sticky=False,
            priority=1,)

# Initialize Alert Object
sufix = '...'
print __module_name__ + ": Initializing" + sufix
rules = Rules()
alerts = SmartAlert(rules)

# Hook Print Events
print __module_name__ + ": Loading hooks" + sufix
xchat.hook_print('Generic Message', alerts.message, userdata=None, priority=xchat.PRI_NORM)
xchat.hook_unload(alerts.unload)
