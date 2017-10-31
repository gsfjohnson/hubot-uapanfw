# Description:
#   Manage black/white lists for UA PA FW.
#
# Dependencies:
#   moment
#
# Configuration:
#   xxxxxxxxxxx [required] - API KEY
#   GRAYLOG_URL (e.g. https://graylog.example.com)
#   GRAYLOG_API_TOKEN (e.g. 098f6bcd4621d373cade4e832627b4f6)
#   GRAYLOG_SEPARATOR (e.g. ','. Default: "\n")
#
#
# Commands:
#   hubot firewall - firewall commands
#
# Notes:
#   requires hubot-auth be present
#
# Author:
#   gfjohnson

fs = require 'fs'
moment = require 'moment'
CIDRMatcher = require 'cidr-matcher'
sprintf = require("sprintf-js").sprintf

modulename = 'fw'
data_file = modulename + ".json"
safety_fail_note = 'If this is time critical ask a human; otherwise please open a ticket.'
displayfmt = '%-4s %-50s %-15s %-10s %s'
timefmt = 'YYYY-MM-DD HH:mm:ss ZZ'
msOneMinute = 60 * 1000
msFiveMinutes = 300 * 1000
glApi = null;

# enable or disable auto-banning
attackAutoBanEnabled = true
attackAutoBanNotifySubscribers = true

# auto-ban after X occurances
attackBanAfterOccurances = 5

# if no attacks detected in this duration, expire counter
attackExpirationHours = 6

# escalating ban durations for 2nd, 3rd, etc duration
attackBanHours = [
  1
  24
  24 * 7
  24 * 30
]

UA_Network = new CIDRMatcher [
  '137.229.0.0/16'
  '199.165.64.0/18'
  '10.0.0.0/8'
  '172.16.0.0/12'
  '192.168.0.0/16'
]

list_names = [
  'blacklist'
  'whitelist'
  'autoban'
]

list_types = [
  'domain'
  'cidr'
  'url'
]

preventDomainBlacklist = [
  [ 'alaska.edu', /alaska\.edu$/ ]
  [ 'uaf.edu', /uaf\.edu$/ ]
]

preventUrlBlacklist = [
  [ 'alaska.edu', /[^\/]+alaska.edu\// ]
  [ 'uaf.edu', /[^\/]+uaf.edu\// ]
]

robotRef = false
fwdata = false

fwnames =
  '10.9.0.252': 'Fairbanks-1'
  '10.9.0.253': 'Fairbanks-2'
  '10.9.128.10': 'Anchorage-1'
  '10.9.128.11': 'Anchorage-2'
  '10.9.192.10': 'Juneau-1'
  '10.9.192.11': 'Juneau-2'

if process.env.HUBOT_AUTH_ADMIN
  admins = process.env.HUBOT_AUTH_ADMIN.split ','
else
  console.warn "#{modulename}: HUBOT_AUTH_ADMIN environment variable not set."

# borrowed from
# http://stackoverflow.com/questions/9796764/how-do-i-sort-an-array-with-coffeescript
sortBy = (key, a, b, r) ->
  r = if r then 1 else -1
  return -1*r if a[key] > b[key]
  return +1*r if a[key] < b[key]
  return 0

isArray = Array.isArray or (obj) -> toString.call(obj) == '[object Array]'

isString = (obj) -> toString.call(obj) == '[object String]'

isObject = (obj) -> toString.call(obj) == '[object Object]'

isAuthorized = (msg) ->
  console.error 'bad robotRef' unless robotRef
  u = msg.envelope.user
  return true if robotRef.auth.hasRole(u,'fw')
  msg.reply "Not authorized.  Missing fw role."
  return false

is2fa = (msg) ->
  console.error 'bad robotRef' unless robotRef
  u = msg.envelope.user
  return true if robotRef.auth.is2fa(u)
  msg.reply "2fa required.  Use `auth 2fa` to validate identity."
  return false


isTerse = (who) ->
  fwdata['terse'] = {} unless 'terse' of fwdata
  return true if who of fwdata.terse && moment(fwdata.terse[who]).isAfter()
  return false

isBanned = (ban_expires) ->
  expires = moment(ban_expires)
  return false unless expires.isValid()
  return true if expires.isAfter()
  return false


oneMinuteWorker = ->
  queryAndProcessAttacks()
  setTimeout oneMinuteWorker, msOneMinute


fiveMinuteWorker = ->
  expireAttackers()
  preExpireNotify 'blacklist'
  preExpireNotify 'whitelist'
  expireEntriesFromList 'blacklist'
  expireEntriesFromList 'whitelist'
  expireEntriesFromList 'autoban'
  setTimeout fiveMinuteWorker, msFiveMinutes


queryAndProcessAttacks = ->
  func_name = 'queryAndProcessAttacks'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  console.log "#{log_date} #{func_name} --"
  return if glApi is null
  #console.log 'exec glApi.get() with glApi.options: ', JSON.stringify glApi.options, null, 2
  glApi.get() (err, res, body) ->
    unless res.statusCode is 200
      return console.warn 'Error requesting Graylog url statusCode=', res.statusCode, 'err=', err, 'options=', glApi.options
    glresponse = JSON.parse body
    #console.log 'glApi returns body:', JSON.stringify jsonbody, null, 2
    events = glresponse.messages.map (m) => m.message
    for event in events
      # skip if already on the attack list
      #continue if fwdata.attackers[event.addrsrc] and fwdata.attackers[event.addrsrc].banned
      # skip unless action
      continue unless event.action in ['block-ip','drop','reset-both']
      # skip if source is internal
      continue if UA_Network.contains event.addrsrc
      addAttackSource event

addAttackSource = (event) ->
  func_name = 'addAttackSource'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  src = event.addrsrc
  ldt = moment(event.timestamp).format('HH:mm:ss')
  unless src of fwdata.attackers
    console.log "#{log_date} #{func_name}: new source #{event.addrsrc}"
    fwdata.attackers[src] =
      attacks: 0
      attacker: src
      victims: []
      created: moment().format()
      banexpires: 0
      msgs: []
  fwdata.attackers[src].attacks++
  fwdata.attackers[src].last = moment().format()
  fwdata.attackers[src].msgs.push "#{ldt} / #{event.source} / #{event.message}"
  if fwdata.attackers[src].msgs.length > attackBanAfterOccurances
    fwdata.attackers[src].msgs.shift()
  if event.addrdst not in fwdata.attackers[src].victims
    fwdata.attackers[src].victims.push event.addrdst
  # ban if attack count exceeds attackBanAfterOccurances value
  if fwdata.attackers[src].attacks >= attackBanAfterOccurances
    # do not ban if already banned
    banAttackSource fwdata.attackers[src] unless isBanned fwdata.attackers[src].banexpires

banAttackSource = (attackSource) ->
  func_name = 'banAttackSource'
  #console.log 'banAttackSource --'
  src = attackSource.attacker
  msgs = attackSource.msgs.join "\n"
  status = 'would have auto-banned'
  status = 'auto-banning' if attackAutoBanEnabled
  attackSource.bancount = 0 unless attackSource['bancount']
  bc = fwdata.attackers[src].bancount
  if attackSource.bancount >= (attackBanHours.length - 1)
    bc = attackBanHours.length - 1
  fwdata.attackers[src].bancount++
  banHours = attackBanHours[bc]
  attackSource.banexpires = moment().add(banHours,'hours').format()
  usermsg = "#{modulename}: #{status} `#{src}` for #{banHours} hours due to" +
    " #{attackBanAfterOccurances} events since" +
    " #{moment(attackSource.created).format('YYYY-MM-DD HH:mm:ss')}"
  usermsg += " and #{bc} previous bans" if bc > 0
  usermsg += ": ```#{msgs}```"
  list_name = 'autoban'
  notifySubscribers list_name, usermsg
  # only notify unless enabled
  return unless attackAutoBanEnabled
  entry = 
    creator: "robot"
    created: moment().format()
    expires: attackSource.banexpires
    type: 'cidr'
    val: attackSource.attacker
    reason: "#{attackSource.attacks} attacks\n#{msgs}"
  result = addListEntry list_name, entry
  if result isnt true
    usermsg = "Failed to add `#{entry.val}` (#{entry.type}) to list" +
      " #{list_name}.  Error: `#{result}`"
    notifySubscribers list_name, usermsg
  
  #notifymsg = "#{entry.creator} added `#{entry.val}` (#{entry.type}) to list"
  #notifymsg += " #{list_name}. Expires `#{entry.expires}`."
  #notifySubscribers list_name, notifymsg

expireAttackers = ->
  func_name = 'expireAttackers'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  console.log "#{log_date} #{func_name} --"
  for src of fwdata.attackers
    attackSource = fwdata.attackers[src]
    # skip if last seen in x duration
    expire = moment(attackSource.last).isBefore( moment().subtract(attackExpirationHours,'hour') )
    continue unless expire
    # skip if currently banned
    continue if attackSource['banexpires'] and isBanned attackSource.banexpires
    # flush it
    console.log "#{moment().format('YYYY-MM-DD HH:mm:ss')} #{func_name}: #{src} "+
      "last seen: #{moment(fwdata.attackers[src].last).fromNow()}"
    delete fwdata.attackers[src]

preExpireNotify = (list_name) ->
  func_name = 'preExpireNotify'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  unless list_name of fwdata.lists
    return console.error "#{log_date} #{func_name}: #{list_name} does not exist"

  list = fwdata.lists[list_name]
  removequeue = []
  expiring = [
    sprintf displayfmt, 'Type', 'Value', 'Expiration', 'Creator', 'Reason'
  ]
  for entry in fwdata.lists[list_name]
    continue if entry.expire_notified
    if moment(entry.expires).valueOf() < ( Date.now() + (3600*1000) )
      entry.expire_notified = true
      reason = ""
      if 'reason' of entry
        reason = entry.reason
        reason = entry.reason.split("\n").shift().substring(0,20) if entry.reason.indexOf("\n") > 0
      expiring.push sprintf displayfmt, entry.type, entry.val,
        moment(entry.expires).fromNow(), entry.creator, reason

  if expiring.length > 1
    usermsg = "fw: #{list_name} entries will expire soon: " +
      "```"+ expiring.join("\n") + "```"
    notifySubscribers list_name, usermsg
    writeData()


expireEntriesFromList = (list_name) ->
  func_name = 'expireEntriesFromList'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')

  unless list_name of fwdata.lists
    return console.error "#{log_date} #{func_name}: #{list_name} does not exist"

  list = fwdata.lists[list_name]
  removequeue = []
  deleted = [
    sprintf displayfmt, 'Type', 'Value', 'Expiration', 'Creator', 'Reason'
  ]
  for entry in fwdata.lists[list_name] when moment(entry.expires).valueOf() < Date.now()
    reason = ""
    if 'reason' of entry
      reason = entry.reason
      reason = entry.reason.split("\n").shift().substring(0,20) if entry.reason.indexOf("\n") > 0
    deleted.push sprintf displayfmt, entry.type, entry.val,
      moment(entry.expires).fromNow(), entry.creator, reason
    removequeue.push entry

  if removequeue.length > 0
    while removequeue.length > 0
      entry = removequeue.shift()
      list.splice(list.indexOf(entry), 1)
    usermsg = "fw: #{list_name} entries expired and have been removed: " +
      "```"+ deleted.join("\n") + "```"
    notifySubscribers list_name, usermsg
    writeData()


notifySubscribers = (list_name, usermsg, current_un = false, who = 'all') ->
  func_name = 'notifySubscribers'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  return console.error "#{log_date} #{func_name}: bad robotRef" unless robotRef
  return console.error "#{log_date} #{func_name}: bad list: #{list_name}" unless list_name in list_names
  return console.error "#{log_date} #{func_name}: list not created: #{list_name}" unless list_name of fwdata.notify
  return console.error "#{log_date} #{func_name}: list empty: #{list_name}" unless isArray fwdata.notify[list_name]
  un_list = who if isArray who
  un_list = [who] if isString who
  un_list = fwdata.notify[list_name] if who == 'all'
  for un in un_list
    console.log "#{log_date} #{func_name} #{un}: #{usermsg}"
    robotRef.send { room: un }, usermsg unless current_un && un == current_un


notifyAdmins = (usermsg, current_un = false) ->
  func_name = 'notifyAdmins'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  console.error "#{log_date} #{func_name}: bad robotRef" unless robotRef
  for un in admins when un.indexOf('U') != 0
    robotRef.send { room: un }, usermsg unless current_un && un == current_un


showAdmins = (robot, msg) ->
  fullcmd = String(msg.match.shift())
  who = msg.envelope.user.name

  logmsg = "#{modulename}: #{who} requested: #{fullcmd}"
  robot.logger.info logmsg

  msg.reply "#{modulename} admins: #{admins.join(', ')}"

  logmsg = "#{modulename}: robot responded to #{who}: " +
    "provided list of admins"
  robot.logger.info logmsg


requestListEntryAddition = (robot, msg) ->
  fullcmd = String(msg.match.shift())
  who = msg.envelope.user.name

  entry =
    creator: who
    created: moment().format()
    expires: moment().add(1, 'months').format()

  list_name = String(msg.match.shift())
  list_name = 'whitelist' if list_name.indexOf('w') == 0
  list_name = 'blacklist' if list_name.indexOf('b') == 0
  list_name = 'autoban' if list_name.indexOf('a') == 0

  l_val = String(msg.match.shift())
  if extra = l_val.match /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2}|))$/
    entry.type = 'cidr'
    entry.val = extra[1]

    # safety check !!
    if entry.val.match /^(?:137\.229\.|199\.165\.|10\.|192\.168\.|172\.[123])/
      usermsg = "Blocking UA CIDRs is not allowed. #{safety_fail_note}"
      logmsg = "#{modulename}: #{who} request failed safety check: #{fullcmd}"
      robot.logger.info logmsg
      msg.reply usermsg
      notifyAdmins "#{logmsg}\nReason: #{usermsg}"
      return

  else if extra = l_val.match /^(?:http:\/\/|)([a-zA-Z0-9][-a-zA-Z0-9\.]+)$/
    entry.type = 'domain'
    entry.val = extra[1]

    # safety check !!
    for arr in preventDomainBlacklist when entry.val.toLowerCase().match arr[1]
      usermsg = "Blocking `#{arr[0]}` is not allowed. #{safety_fail_note}"
      logmsg = "#{modulename}: #{who} request failed safety check: #{fullcmd}"
      robot.logger.info logmsg
      msg.reply usermsg
      notifyAdmins "#{logmsg}\nReason: #{usermsg}"
      return

  else
    entry.type = 'url'
    entry.val = l_val
    if entry.val.toLowerCase().indexOf('https://') == 0
      usermsg = "#{list_name}ing of https links not supported."
      return msg.reply usermsg
    if entry.val.toLowerCase().indexOf('http://') == 0
      entry.val = entry.val.replace(/http:\/\//i,'')

    # safety check !!
    for arr in preventUrlBlacklist when entry.val.toLowerCase().match arr[1]
    #if entry.val.toLowerCase().match /[^\/]+(?:alaska|uaf)\.edu/
      usermsg = "Blocking `#{arr[0]}` is not allowed. #{safety_fail_note}"
      logmsg = "#{modulename}: #{who} request failed safety check: #{fullcmd}"
      robot.logger.info logmsg
      msg.reply usermsg
      notifyAdmins "#{logmsg}\nReason: #{usermsg}"
      return

  expires = String(msg.match.shift())
  if expires isnt 'undefined'
    extra = expires.match /\+(\d+)([a-zA-Z]+)/
    if extra?
      n = extra[1]
      unit = extra[2]
      unless unit in ['h','hours','d','days','w','weeks','M','months','Q','quarters','y','years']
        usermsg = "Invalid unit `#{unit}` in expiration `#{expires}`. Use h or hours, d or days, w or weeks, M or months, Q or quarters, y or years."
        return msg.reply usermsg
      entry.expires = moment().add(n,unit).format()
    else if moment(expires).isValid()
      entry.expires = moment(expires).format()
    else
      usermsg = "invalid expiration date: #{expires}"
      return msg.reply usermsg
  
  result = addListEntry list_name, entry
  if result isnt true
    usermsg = "Failed to add `#{entry.val}` (#{entry.type}) to fw #{list_name}."
    usermsg += "  Error: `#{result}`"
    msg.send usermsg

  usermsg = "Added `#{entry.val}` (#{entry.type}) to fw #{list_name}."
  usermsg += "  Expires `#{entry.expires}`." if expires isnt 'undefined'
  usermsg += "  Change will be applied in < 5 minutes." unless isTerse who
  msg.send usermsg

  logmsg = "#{modulename}: robot responded to #{who}: " +
    "added entry to #{list_name}"
  robot.logger.info logmsg

  notifymsg = "#{who} added `#{entry.val}` (#{entry.type}) to fw #{list_name}."
  notifymsg += "  Expires `#{entry.expires}`." if expires isnt 'undefined'
  notifySubscribers list_name, notifymsg, who

  # be terse after the first utterance
  fwdata.terse[who] = moment().add(30,'minutes').format()

addListEntry = (list_name, entry) ->
  func_name = 'addListEntry'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')

  # validate correct list_name
  unless list_name in list_names
    return "invalid list #{list_name}"
  unless entry['creator']
    return "invalid creator"
  unless entry['created']
    return "invalid created"

  logmsg = "#{modulename}: #{func_name}: #{entry.creator} requested:"
  logmsg += " #{list_name} #{entry.type} #{entry.val}"
  logmsg += " expires #{moment(entry.expires).format(timefmt)}"
  robotRef.logger.info logmsg

  fwdata.lists[list_name] = [] unless list_name of fwdata.lists
  fwdata.lists[list_name].push entry
  writeData()

  logmsg = "#{modulename}: #{func_name}: #{entry.creator} added"
  logmsg += " #{list_name} #{entry.type} #{entry.val}"
  logmsg += " expires #{moment(entry.expires).fromNow()}"
  robotRef.logger.info logmsg

  return true

extendListEntry = (robot, msg) ->
  fullcmd = String(msg.match.shift())
  who = msg.envelope.user.name

  list_name = String(msg.match.shift())
  list_name = 'whitelist' if list_name.indexOf('w') == 0
  list_name = 'blacklist' if list_name.indexOf('b') == 0
  list_name = 'autoban' if list_name.indexOf('a') == 0

  l_search = String(msg.match.shift())

  if l_search.toLowerCase().indexOf('https://') == 0
    usermsg = "#{list_name}ing of https links not supported."
    return msg.reply usermsg

  if l_search.toLowerCase().indexOf('http://') == 0
    l_search = l_search.replace(/http:\/\//i,'')

  logmsg = "#{modulename}: #{who} requested: #{list_name} extend #{l_search}"
  robot.logger.info logmsg

  # check for matches
  matches = 0
  entry = undefined
  for entry in fwdata.lists[list_name] when entry.val.indexOf(l_search) > -1
    #console.log "entry.type: [#{entry.type}] l_search: [#{l_search}] entry.val: [#{entry.val}]"
    if entry.val.indexOf(l_search) > -1
      #console.log "l_search: [#{l_search}] MATCHED entry.val: [#{entry.val}]"
      matches++
      entry = entry
  if matches != 1
    usermsg = "search matched zero or more than a single entry; " +
      "improve search term and try again"
    return msg.reply usermsg
  #console.log entry

  expires = String(msg.match.shift())
  if expires is 'undefined'
    usermsg = "you must provide a new absolute or relative expiration"
    return msg.reply usermsg

  extra = expires.match /(-|\+|)(\d+)([a-zA-Z])/
  if extra?
    direction = extra.shift()
    n = extra.shift()
    unit = extra.shift()
    unless unit in ['h','d','w','M','Q','y']
      usermsg = "Invalid unit `#{unit}` in expiration `#{expires}`. Use h for hours, d for days, w for weeks, M for months, Q for quarters, or y for years."
      return msg.reply usermsg
    if direction == '+'
      entry.expires = moment(entry.expires).add(n,unit).format()
    else if direction == '-'
      entry.expires = moment(entry.expires).subtract(n,unit).format()
    else
      entry.expires = moment().add(n,unit).format()
  else if moment(expires).isValid()
    entry.expires = moment(expires).format()
  else
    usermsg = "invalid expiration date: #{expires}"
    return msg.reply usermsg

  obj.expire_notified = false

  logmsg = "#{modulename}: #{who} requested: " +
    "#{list_name} #{entry.type} #{entry.val} new expiration #{moment(entry.expires).format(timefmt)}"
  robot.logger.info logmsg

  writeData()

  usermsg = "#{who} updated expiration for `#{entry.val}` #{list_name}ing."
  usermsg += "  New expiration `#{entry.expires}`."
  msg.reply usermsg

  logmsg = "#{modulename}: robot responded to #{who}: " +
    "updated entry in #{list_name}"
  robot.logger.info logmsg

  notifySubscribers list_name, usermsg, who


deleteListEntry = (robot, msg) ->
  fullcmd = String(msg.match.shift())
  who = msg.envelope.user.name

  list_name = String(msg.match.shift())
  list_name = 'whitelist' if list_name.indexOf('w') == 0
  list_name = 'blacklist' if list_name.indexOf('b') == 0
  list_name = 'autoban' if list_name.indexOf('a') == 0

  #l_type = String(msg.match.shift())
  l_type = false
  l_search = String(msg.match.shift())

  if l_search.toLowerCase().indexOf('https://') == 0
    usermsg = "#{list_name}ing of https links not supported."
    return msg.reply usermsg

  if l_search.toLowerCase().indexOf('http://') == 0
    l_search = l_search.replace(/http:\/\//i,'')

  logmsg = "#{modulename}: #{who} requested: " +
    "#{list_name} delete #{l_type ? l_type : ''} #{l_search}"
  robot.logger.info logmsg

  deleted = []
  new_entry = []
  deleted.push sprintf displayfmt, 'Type', 'Value', 'Expiration', 'Creator', 'Reason'
  for entry in fwdata.lists[list_name]
    expires = moment(entry.expires)
    if l_type and l_type != entry.type
      new_entry.push entry
      continue
    if l_search and entry.val.indexOf(l_search) == -1
      new_entry.push entry
      continue
    if expires.isBefore() # now
      new_entry.push entry
      continue
    reason = ""
    if 'reason' of entry
      reason = entry.reason
      reason = entry.reason.split("\n").shift().substring(0,20) if entry.reason.indexOf("\n") > 0
    deleted.push sprintf displayfmt, entry.type, entry.val,
      expires.fromNow(), entry.creator, reason

  deltaN = fwdata.lists[list_name].length - new_entry.length
  if deltaN > 0
    usermsg = "#{who} removed `#{deltaN}` fw #{list_name} entries."
    usermsg += "  Change will be applied in < 5 minutes." unless isTerse who
    usermsg += "  Removed: ```"+ deleted.join("\n") + "```"
    fwdata.lists[list_name] = new_entry
    writeData()
  else
    usermsg = "#{list_name} delete request did not match any records."
  msg.reply usermsg

  logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
    "removed #{deltaN} entries from #{list_name}"
  robot.logger.info logmsg

  if deltaN > 0
    #usermsg = usermsg.replace(/  Change will be applied in \< 5 minutes\./, '')
    notifySubscribers list_name, usermsg, who


showList = (robot, msg) ->
  func_name = 'showList'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')

  list_name = String(msg.match[1])
  list_name = 'whitelist' if list_name.indexOf('w') == 0
  list_name = 'blacklist' if list_name.indexOf('b') == 0
  list_name = 'autoban' if list_name.indexOf('a') == 0

  l_type = false
  l_search = false
  if msg.match[2]?
    l_search = String(msg.match[2])

  logmsg = "#{modulename}: #{func_name}: #{msg.envelope.user.name} requested: show list #{list_name}"
  robot.logger.info logmsg

  unless list_name of fwdata.lists and fwdata.lists[list_name].length > 0
    return msg.send "No entries on list #{list_name}."

  epb = 20 # entries per block
  i = 0 # entries
  arr = [] # temp container
  output = [] # output blocks
  arr.push sprintf displayfmt, 'Type', 'Value', 'Expiration', 'Creator', 'Reason'
  for entry in fwdata.lists[list_name]
    expires = moment(entry.expires)
    if l_type and l_type != entry.type
      continue
    if l_search and entry.val.indexOf(l_search) == -1
      continue
    if expires.isBefore() # now
      continue
    i++
    if arr.length >= epb
      output.push arr.join("\n")
      arr = []
    else
      reason = ""
      if 'reason' of entry
        reason = entry.reason
        reason = entry.reason.split("\n").shift().substring(0,20) if entry.reason.indexOf("\n") > 0
      arr.push sprintf displayfmt, entry.type, entry.val,
        expires.fromNow(), entry.creator, reason
      singlemsg = "#{entry.creator} added `#{entry.val}` (#{entry.type}) to list"
      singlemsg += " #{list_name}. Expires #{moment(entry.expires).fromNow()}."
      singlemsg += " Reason: ```#{entry.reason}```" if 'reason' of entry

  if arr.length > 0
    output.push arr.join("\n")
  
  if i > 1
    msg.send "Here is the current #{list_name}:\n"
    msg.send "```#{ob}\n```" for ob in output
  if i == 1
    msg.send singlemsg

  logmsg = "#{modulename}: #{func_name}: robot responded to #{msg.envelope.user.name}: " +
    "displayed #{list_name} items and expirations"
  robot.logger.info logmsg


subscribe = (robot, msg) ->
  user = msg.envelope.user
  list_name = msg.match[1]
  list_name = 'whitelist' if list_name.indexOf('w') == 0
  list_name = 'blacklist' if list_name.indexOf('b') == 0
  list_name = 'autoban' if list_name.indexOf('a') == 0
  who = user.name
  who = msg.match[2] if msg.match[2]

  logmsg = "#{modulename}: #{user.name} requested: subscribe #{list_name} #{who}"
  robot.logger.info logmsg

  fwdata.notify[list_name] = [] unless list_name of fwdata.notify
  fwdata.notify[list_name].push who unless who in fwdata.notify[list_name]

  usermsg = "Added `#{who}` to list #{list_name}."
  msg.reply usermsg

  logmsg = "#{modulename}: robot responded to #{user.name}: " +
    "added #{who} to list #{list_name}"
  robot.logger.info logmsg

  writeData()


unsubscribe = (robot, msg) ->
  user = msg.envelope.user
  list_name = msg.match[1]
  list_name = 'whitelist' if list_name.indexOf('w') == 0
  list_name = 'blacklist' if list_name.indexOf('b') == 0
  list_name = 'autoban' if list_name.indexOf('a') == 0
  who = msg.envelope.user.name
  who = msg.match[2] if msg.match[2]

  logmsg = "#{modulename}: #{user.name} requested: unsubscribe #{list_name} #{who}"
  robot.logger.info logmsg

  unless list_name of fwdata.notify
    usermsg = "No such list #{list_name}."
    return msg.reply usermsg

  n = fwdata.notify[list_name].indexOf(who)
  unless n > -1
    usermsg = "`#{who}` not a member of list #{list_name}."
    return msg.reply usermsg

  fwdata.notify[list_name].splice(n, 1)

  usermsg = "Removed `#{who}` from list #{list_name}."
  msg.reply usermsg

  logmsg = "#{modulename}: robot responded to #{user.name}: " +
    "removed #{who} from list #{list_name}"
  robot.logger.info logmsg

  writeData()


showSubscribers = (robot, msg) ->
  func_name = 'showSubscribers'
  who = msg.envelope.user.name
  list_name = ''

  list_name = msg.match[1] if msg.match[1]
  list_name = 'whitelist' if list_name.indexOf('w') == 0
  list_name = 'blacklist' if list_name.indexOf('b') == 0
  list_name = 'autoban' if list_name.indexOf('a') == 0

  logmsg = "#{modulename}: #{func_name}: #{who} requested subscribers"
  logmsg += " for list #{list_name}" if list_name
  robot.logger.info logmsg

  usermsg = ""
  for list of fwdata.notify
    continue if list_name and list != list_name
    continue unless isArray(fwdata.notify[list]) and fwdata.notify[list].length > 0
    usermsg += "Subscribers for #{list}: `"+ fwdata.notify[list].join('`, `') + "`\n\n"
  if usermsg
    msg.reply usermsg

  logmsg = "#{modulename}: #{func_name}: displayed subscribers to #{who}"
  robot.logger.info logmsg


httpGetHelp = (robot, req, res) ->
  func_name = 'httpGetHelp'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')

  clientip = req.connection.remoteAddress || req.socket.remoteAddress ||
    req.connection.socket.remoteAddress

  logmsg = "#{modulename}: #{func_name}: web request from #{clientip}"
  robot.logger.info logmsg

  arr = ["<html>\n<body>\n<pre>\n"]
  for list in list_names
    for type in list_types
      arr.push "<a href='#{list}/#{type}'>#{list}/#{type}</a>\n"
  arr.push "</pre>\n</body>\n</html>\n"
  res.setHeader 'content-type', 'text/html'
  res.end arr.join "\n"

  logmsg = "#{modulename}: #{func_name}: robot responded to web request"
  robot.logger.info logmsg


httpGetList = (robot, req, res, list_name, list_type) ->
  func_name = 'httpGetList'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  clientip = req.connection.remoteAddress || req.socket.remoteAddress ||
    req.connection.socket.remoteAddress

  rememberCheckin clientip, list_name, list_type

  logmsg = "#{modulename}: #{func_name}: web request from #{clientip}: get #{list_type} #{list_name}"
  robot.logger.info logmsg

  arr = []
  if list_name of fwdata.lists
    for obj in fwdata.lists[list_name]
      if obj.type == list_type and moment(obj.expires).isAfter()
        arr.push obj.val
  content = '# nothing here yet! #'
  content = arr.join "\n" if arr.length
  res.setHeader 'content-type', 'text/plain'
  res.end content

  logmsg = "#{modulename}: robot responded to web request: sent #{list_type} #{list_name}"
  robot.logger.info logmsg


showCheckins = (robot, msg) ->
  who = msg.envelope.user.name

  logmsg = "#{modulename}: #{who} requested: checkins"
  robot.logger.info logmsg

  arr = []
  for obj in fwdata.firewalls
    obj.checkin = moment(obj.checkin) if typeof(obj.checkin) is 'string'
    arr.push sprintf '%-16s %-10s %-10s %-15s', obj.name, obj.list, obj.type,
      obj.checkin.fromNow()
  usermsg = "Expected firewall check times: ```"+ arr.join("\n") + "```"
  msg.send usermsg

  logmsg = "#{modulename}: robot responded to #{who}: checkins"
  robot.logger.info logmsg


rememberCheckin = (clientip,list_name,l_type) ->
  return unless fwname = fwnames[clientip] # skip non-firewalls
  for obj in fwdata.firewalls
    if obj.ip is clientip and obj.type is l_type and obj.list is list_name
      obj.checkin = moment().add(5,'minutes')
      writeData()
      return
  # otherwise create new object
  obj =
    ip: clientip
    name: fwname
    list: list_name
    type: l_type
    checkin: moment().add(5,'minutes')
  fwdata.firewalls.push obj
  if fwdata.firewalls.length > 1
    fwdata.firewalls = fwdata.firewalls.sort (a,b) ->
      sortBy('name',a,b) or sortBy('list',a,b) or sortBy('type',a,b)
  writeData()

showHelp = (robot, msg) ->
  who = msg.envelope.user.name
  arr = [
    "#{modulename} show list <list> [searchterm]"
    "#{modulename} add <list> <domain.tld|weburl.tld/etc|x.x.x.x> [+7d]"
    "#{modulename} del <list> <domain.tld|weburl.tld/etc|x.x.x.x>"
    "#{modulename} extend <list> <weburl.tld/etc|x.x.x.x> [[+-]20d]"
    "#{modulename} subscribe <list> [username] - subscribe to change notifications"
    "#{modulename} unsubscribe <list> [username]"
    "#{modulename} show subscribers [list]"
  ]

  cmds = ['```']
  cmds.push str for str in arr
  cmds.push '```'

  msg.reply cmds.join "\n"

  logmsg = "#{modulename}: robot responded to #{who}: " +
    "displayed #{modulename} help"
  robot.logger.info logmsg


writeData = ->
  fs.writeFileSync data_file, JSON.stringify(fwdata), 'utf-8'
  logmsg = "#{modulename}: wrote #{data_file}"
  robotRef.logger.info logmsg


module.exports = (robot) ->

  robotRef = robot
  if process.env.HUBOT_GRAYLOG_URL && process.env.HUBOT_GRAYLOG_TOKEN
    glApi = robot.http process.env.HUBOT_GRAYLOG_URL
    glApi.auth process.env.HUBOT_GRAYLOG_TOKEN, 'token'
    glApi.path 'api/search/universal/relative'
    glApi.header 'Accept', 'application/json'
    q =
      query: 'logfile:THREAT\\/vulnerability',
      fields: 'message,source,addrsrc,addrdst,action',
      range: 60,
      decorate: 'true'
    glApi.query q
  else
    console.warn "#{modulename}: HUBOT_GRAYLOG_URL and HUBOT_GRAYLOG_TOKEN" +
      " environment variables not set."
  setTimeout oneMinuteWorker, 5 * 1000
  setTimeout fiveMinuteWorker, msFiveMinutes

  try
    fwdata = JSON.parse fs.readFileSync data_file, 'utf-8'
    robot.logger.info "#{modulename}: read #{data_file}" if robot.logger
    fwdata =              {} unless isObject fwdata
    fwdata['notify'] =    {} unless isObject fwdata['notify']
    fwdata['lists'] =     {} unless isObject fwdata['lists']
    fwdata['firewalls'] = [] unless isArray fwdata['firewalls']
    fwdata['terse'] =     {} unless isObject fwdata['terse']
    fwdata['attackers'] = {} unless isObject fwdata['attackers']
  catch error
    unless error.code is 'ENOENT'
      console.log("#{modulename}: unable to read #{data_file}: ", error)

  robot.router.get "/#{robot.name}/#{modulename}", (req, res) ->
    return httpGetHelp robot, req, res

  robot.router.get "/#{robot.name}/#{modulename}/blacklist/url", (req, res) ->
    return httpGetList robot, req, res, 'blacklist', 'url'

  robot.router.get "/#{robot.name}/#{modulename}/blacklist/cidr", (req, res) ->
    return httpGetList robot, req, res, 'blacklist', 'cidr'

  robot.router.get "/#{robot.name}/#{modulename}/blacklist/domain", (req, res) ->
    return httpGetList robot, req, res, 'blacklist', 'domain'

  robot.router.get "/#{robot.name}/#{modulename}/whitelist/url", (req, res) ->
    return httpGetList robot, req, res, 'whitelist', 'url'

  robot.router.get "/#{robot.name}/#{modulename}/whitelist/cidr", (req, res) ->
    return httpGetList robot, req, res, 'whitelist', 'cidr'

  robot.router.get "/#{robot.name}/#{modulename}/whitelist/domain", (req, res) ->
    return httpGetList robot, req, res, 'whitelist', 'domain'

  robot.router.get "/#{robot.name}/#{modulename}/autoban/cidr", (req, res) ->
    return httpGetList robot, req, res, 'autoban', 'cidr'

  robot.respond /(?:firewall|fw)(?: help| h|)$/, (msg) ->
    return showHelp robot, msg

  robot.respond /(?:firewall|fw) show (?:admins)$/i, (msg) ->
    return showAdmins robot, msg

  robot.respond /(?:firewall|fw) show (?:checkins|firewalls|fw)$/i, (msg) ->
    return showCheckins robot, msg

  robot.respond /(?:firewall|fw)(?: show|) subscribers(?: (.+)|)$/i, (msg) ->
    return showSubscribers robot, msg

  robot.respond /(?:firewall|fw) show list ([^ ]+)(?: (.+)|)$/i, (msg) ->
    return showList robot, msg

  robot.respond /(?:firewall|fw) (?:add|a) ([^ ]+) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    return unless isAuthorized msg
    return unless is2fa msg

    return requestListEntryAddition robot, msg

  robot.respond /(?:firewall|fw) (?:delete|del|d) ([^ ]+) ([^ ]+)$/i, (msg) ->
    return unless isAuthorized msg
    return unless is2fa msg

    return deleteListEntry robot, msg

  robot.respond /(?:firewall|fw) (?:extend|ext|e) ([^ ]+) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    return unless isAuthorized msg
    return unless is2fa msg

    return extendListEntry robot, msg

  robot.respond /(?:firewall|fw) (?:subscribe|sub) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    return subscribe robot, msg

  robot.respond /(?:firewall|fw) (?:unsubscribe|unsub) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    return unsubscribe robot, msg

  robot.respond /(?:firewall|fw) unban ([0-9\.]+)$/i, (msg) ->
    return unban robot, msg

