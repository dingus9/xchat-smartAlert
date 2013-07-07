import xchat
import gntp.notifier
import os
import platform
import psutil
import re
import time
#import threading

__module_name__ = "smartAlert"
__module_version__ = "1.5"
__module_description__ = "Customize XChat Alerting + Logging"


# Define all match rules and result callbacks here.
class Rules(dict):

    def __init__(self):

        self.chain = {'end': 0,
                      'cont': 1,
                      'abort': 2}

        self.rules = ({'mention': True,
                      'callback': self._mention},
                      {'channels': ['**private'],
                       'callback': self._mention},
                      {'channels': ['cloudoutage'],
                      'callback': self._important},
                      {'users': ['nebnotify'],
                      'str': 'HMDB ETL',
                      'bool': 'and',
                      'callback': self._hosting_matrix_etl,
                      'eat': xchat.EAT_NONE},
                      {'users': ['meow_bot', 'maas-bot'],
                      'callback': self._maas_alert_bot},
                      {'channels': ['#nebopsadmins', '#nebops', '#NebOps'],
                      'callback': self._nebops_activity},
                      )

        # used for alert timout queues in callback methods
        self.alerts = {'maas_issue': {'timeout': 120},
                       'nicks_user': {'timeout': 30},
                       'nebops_alert': {'timeout': 60},
                       'flood_threshhold': {'flood_limit': 10, 'flood_persec': 1,
                                            'timeout': 10}}

    def eat(self, rule):
        if 'eat' in self.rules[rule].keys():
            return self.rules[rule]['eat']
        else:
            return 'none'

    def filter_match(self, user, channel, message, nick):
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
                    if message.find(test) > -1:
                        rslt['str'] = True
                    else:
                        rslt['str'] = False
                elif name == 'channels':
                    rslt.setdefault('channels', False)
                    for chan in test:
                        if xchat.nickcmp(chan, channel) == 0:
                            rslt['channels'] = True
                            continue
                elif name == 'mention':
                    rslt['mention'] = False
                    if message.find(nick) > -1:
                        rslt['mention'] = True
                        continue

            if 'bool' in rule:
                if rule['bool'] == 'or' and any(rslt.values()):
                    retval = rule
                    break
            elif all(rslt.values()):
                retval = rule
                break

        if retval:
            return retval
        else:
            return None

    def _mention(self, scope, user, channel, string, nick):
        message = string
        title = {'**private': "PM: " + user}.get(channel, "Mention: " + channel)
        return {'notif': 'Message', 'message': user + ': ' + message, 'title': title}

    def _important(self, scope, user, channel, string, nick):
        message = user + ': ' + string
        title = 'Important on: ' + channel
        return {'notif': 'Message', 'mesage': message, 'title': title}

    def _hosting_matrix_etl(self, scope, user, channel, string, nick):
        reg = re.compile('(.*) - (SUCCESS|INFO|ALERT|.*) - - HMDB ETL \((.*)\) (.*)')
        match = reg.match(string)
        groups = match.groups()
        return {'notif': 'Cron', 'message': groups[2].upper() + "->ETL: " +
                groups[1] + ' - ' + groups[3],
                'title': 'something'}

    def _maas_alert_bot(self, scope, user, channel, string, nick):
        if self._alert_timeout('maas_issue'):
            message = None
            if user == 'meow_bot':
                match = re.compile('(.+) (.+) (.+): (.+) (.+) - (.+):([0-9]{3}) .+').match(string)
                if match:
                    groups = match.groups()
                    if len(groups) > 4:
                        message = user + ':' + groups[2] + ' ' + groups[3] + ':' + \
                            groups[4] + ':' + groups[5]
            elif user == 'maas-bot':
                match = re.compile('(.+) (.+) (.+): (.+) (.+) - .+Found:([0-9]{3}) .+').match(string)
                if match:
                    groups = match.groups()
                    if len(groups) > 3:
                        message = user + ':' + groups[2] + ' ' + groups[3] + ':' + \
                            groups[4] + ':' + groups[5]
            title = "MaaS Alert"
            if message:
                return {'notif': 'Alert', 'message': message, 'title': title}

        return None

    def _nebops_activity(self, scope, user, channel, string, nick):
        if self._alert_timeout('nebops_alert'):
            message = channel + " >> " + user + ': ' + string
            title = "Neb Activity"
            return {'notif': 'Message', 'message': message, 'title': title}
        else:
            return None

    def _anymessage(self, scope, user, channel, string, nick):
        result = None
        #if self._alert_timeout('nicks_user'):
        #    result = channel + " >> " + user + ': ' + string
        result = channel + " >> " + user + ': ' + string
        return result

    # Checks for timeout, returns true if timeout met or false if timeout still in effect.
    # Name string, an key of self.alerts "[name]", may be shared between callbacks if desired.
    def _alert_timeout(self, name):
        now = int(time.time())
        if 'timeout' in self.alerts[name].keys():
            timeout = self.alerts[name]['timeout']
            seen = self.alerts[name].get('seen', now)
            if seen == now or now > seen + timeout:
                self.alerts[name]['seen'] = now
                return True
            else:
                return False

    # Check name for flooding
    def _alert_flood(self, name):
        if name in self.alerts and 'flood_limit' in self.alerts[name]:
            now = int(time.time())
            count = self.alerts[name].get('count', 0)
            timeout = self.alerts[name]['flood_persec']
            seen = self.alerts[name].get('flood_seen', now)
            if now > seen + timeout and count <= self.alerts[name].get('flood_limit', 10):
                self.alerts[name]['flood_seen'] = now
                self.alerts[name]['flood_count'] = 0
                return True
            else:
                self.alerts[name]['flood_count'] += 1
                return self._alert_timeout(name)


class SmartAlert():
    def __init__(self, rules):
        print self.__class__.__name__ + ": Loading" + sufix
        pid = psutil.Process(os.getpid())
        self.appname = pid.name
        self.rules = rules
        self.alerters = []
        self.hooked = []
        self.hooked_timer = None
        self.os = platform.system()
        if self.os == 'Darwin':  # Handle special osx container setup
            self.icon = os.getenv("HOME") + "/xchat.png"
        else:
            self.icon = None

        # Setup Alerting Environment
        self.notifs = ('Message', 'Alert', 'Notify', 'Cron')

        # Register growl alerter
        self.addAlerter(Growlify(self.notifs, self.appname, self.icon))

    def command(self, word, word_eol, userdata):
        command = word[0]
        if len(word) > 1:
            params = word[1]
        else:
            params = ''
            print "usage: " + command + " hooked | rehook"

        if params == 'hooked':
            print self.hooked
        elif params == 'rehook':
            self.xchatHook()
        return xchat.EAT_ALL

    def addAlerter(self, alerter):
        print "Registering Alerter: " + alerter.__class__.__name__ + "..."
        self.alerters.append(alerter)
        alerter.alert(self.notifs[0], self.__class__.__name__, 'Initializing alerter')

    # Message is the main callback for a generic message event.
    # it assumes no command was issued so it should only be bound to a message even type.
    def general_message(self, word, word_eol, userdata):
        # user and message detection is arbitrary to xchat... might want to look at
        # a more dynamic IRC formmating method for determining the message user and
        # other attributes.
        if len(word) == 2:
            user = word[0]
            message = word[1]
        elif len(word) == 3 and word[2] == '@':
            user = word[0]
            message = word[1]
        else:
            user = ''
            message = ''
            print word
        channel = xchat.get_info('channel')
        scope = xchat.get_info('server')
        self.base_message(user, message, channel, scope)

    def private_message(self, word, word_eol, userdata):
        if len(word) == 2:
            user = word[0]
            message = word[1]
        elif len(word) == 3 and word[2] == '@':
            user = word[0]
            message = word[1]
        channel = '**private'
        scope = xchat.get_info('server')
        self.base_message(user, message, channel, scope)

    # Called once user, message, channel, and scope have been parsed
    def base_message(self, user, message, channel, scope):
        nick = xchat.get_info('nick')
        notify = None
        # Match on one rule for now, later we might support multi matches for multi dests
        # or what ever. But right now I'm only needing growl and one type of match.
        matched = self.rules.filter_match(user, channel, message, nick)
        if matched:
            if 'callback' in matched:
                notify = matched['callback'](scope, user, channel, message, nick)
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

    def joiner(self, word, word_eol, userdata):
        nick = xchat.get_info('nick')
        if word[0].find(nick) > -1:
            timeout = 3
            if len(self.hooked):
                for handler in self.hooked:
                    xchat.unhook(handler)
                self.hooked = []
            self._hook_wait = time.time()
            if not self.hooked_timer:
                print 'register hook timer'
                self.hooked_timer = xchat.hook_timer(timeout * 1000,
                                                     self._xchatHookTest,
                                                     (timeout))
            #threading.Timer(timeout, self._xchatHookTest, (timeout, )).run()

    # Used in joiner above
    def _xchatHookTest(self, timeout):
        print 'hooked timer'
        print time.time()
        print self._hook_wait
        print timeout
        if time.time() >= self._hook_wait + timeout:
            if self.hooked_timer:
                print 'hooked timer unhooked'
                xchat.unhook(self.hooked_timer)
                self.hooked_timer = None
            self.xchatHook()

    def xchatHook(self):
        print 'rehooking'
        if not len(self.hooked):
            self.hooked = [xchat.hook_print('Channel Message', alerts.general_message,
                                        userdata=None, priority=xchat.PRI_NORM),
                       xchat.hook_print('Channel Msg Hilight', alerts.general_message,
                                        userdata=None, priority=xchat.PRI_NORM),
                       xchat.hook_print('Private Message', alerts.private_message,
                                        userdata=None, priority=xchat.PRI_NORM),
                       xchat.hook_print('Private Message to Dialog',
                                        alerts.private_message, userdata=None,
                                        priority=xchat.PRI_NORM)]

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

# add channel hooks on join... also unloads and reloads every join...
# prevents floods!
xchat.hook_command('SMARTALERT', alerts.command, userdata=None, priority=xchat.PRI_HIGHEST)
xchat.hook_server('JOIN', alerts.joiner, userdata=None, priority=xchat.PRI_HIGHEST)
alerts.xchatHook()
xchat.hook_unload(alerts.unload)
