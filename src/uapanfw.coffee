# Description:
#   Manage black/white lists for UA PA FW.
#
# Dependencies:
#   moment
#
# Configuration:
#   xxxxxxxxxxx [required] - API KEY
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
#ipaddr = require 'ipaddr.js'
sprintf = require("sprintf-js").sprintf

modulename = 'fw'
data_file = modulename + ".json"
safety_fail_note = 'If this is time critical ask a human; otherwise please open a ticket.'
displayfmt = '%-4s %-50s %-15s %s'
timefmt = 'YYYY-MM-DD HH:mm:ss ZZ'
svcQueueIntervalMs = 300 * 1000

#preventCidrBlacklist = [
#  ipaddr.parseCIDR '137.229.0.0/16'
#  ipaddr.parseCIDR '199.165.64.0/18'
#  ipaddr.parseCIDR '10.0.0.0/8'
#  ipaddr.parseCIDR '172.16.0.0/12'
#  ipaddr.parseCIDR '192.168.0.0/16'
#]

preventDomainBlacklist = [
  [ 'alaska.edu', /alaska\.edu$/ ]
  [ 'uaf.edu', /uaf\.edu$/ ]
]

preventUrlBlacklist = [
  [ 'alaska.edu', /[^\/]+alaska.edu\// ]
  [ 'uaf.edu', /[^\/]+uaf.edu\// ]
]

robotRef = false
fwdata =
  notify: []
  blacklist: []
  whitelist: []
  firewalls: []
  terse: {}

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


expirationWorker = ->
  preExpireNotify 'blacklist'
  preExpireNotify 'whitelist'
  expireEntriesFromList 'blacklist'
  expireEntriesFromList 'whitelist'
  setTimeout expirationWorker, svcQueueIntervalMs


preExpireNotify = (list_name) ->
  list = fwdata[list_name]
  removequeue = []
  expiring = [
    sprintf displayfmt, 'Type', 'Value', 'Expiration', 'Creator'
  ]
  for obj in fwdata[list_name]
    continue if obj.expire_notified
    if moment(obj.expires).valueOf() < ( Date.now() + (3600*1000) )
      obj.expire_notified = true
      expiring.push sprintf displayfmt, obj.type, obj.val,
        moment(obj.expires).fromNow(), obj.creator

  if expiring.length > 1
    usermsg = "fw: #{list_name} entries will expire soon: " +
      "```"+ expiring.join("\n") + "```"
    notifySubscribers usermsg
    writeData()


expireEntriesFromList = (list_name) ->
  list = fwdata[list_name]
  removequeue = []
  deleted = [
    sprintf displayfmt, 'Type', 'Value', 'Expiration', 'Creator'
  ]
  for obj in fwdata[list_name] when moment(obj.expires).valueOf() < Date.now()
    deleted.push sprintf displayfmt, obj.type, obj.val,
      moment(obj.expires).fromNow(), obj.creator
    removequeue.push obj

  if removequeue.length > 0
    while removequeue.length > 0
      obj = removequeue.shift()
      list.splice(list.indexOf(obj), 1)
    usermsg = "fw: #{list_name} entries expired and have been removed: " +
      "```"+ deleted.join("\n") + "```"
    notifySubscribers usermsg
    writeData()


notifySubscribers = (usermsg, current_un = false) ->
  console.error 'bad robotRef' unless robotRef
  for un in fwdata.notify
    robotRef.send { room: un }, usermsg unless current_un && un == current_un


notifyAdmins = (usermsg, current_un = false) ->
  console.error 'bad robotRef' unless robotRef
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


addListEntry = (robot, msg) ->
  fullcmd = String(msg.match.shift())
  who = msg.envelope.user.name

  entry =
    creator: who
    created: moment().format()
    expires: moment().add(1, 'months').format()

  list_name = String(msg.match.shift())
  list_name = 'whitelist' if list_name.indexOf('w') == 0
  list_name = 'blacklist' if list_name.indexOf('b') == 0

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

  else if extra = l_val.match /^([a-zA-Z][a-zA-Z0-9\.]+)$/
    entry.type = 'domain'
    entry.val = extra[1]

    # safety check !!
    for arr in preventDomainBlacklist when entry.val.toLowerCase().match arr[1]
    #if entry.val.toLowerCase().match /(?:alaska|uaf)\.edu$/
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
  
  logmsg = "#{modulename}: #{who} requested: " +
    "#{list_name} #{entry.type} #{entry.val} expires #{moment(entry.expires).format(timefmt)}"
  robot.logger.info logmsg

  fwdata[list_name].push entry
  writeData()

  usermsg = "Added `#{entry.val}` to fw #{list_name}."
  if expires != 'undefined'
    usermsg += "  Expires `#{entry.expires}`."
  unless isTerse who
    usermsg += "  Change will be applied in < 5 minutes."
  msg.send usermsg

  logmsg = "#{modulename}: robot responded to #{who}: " +
    "added entry to #{list_name}"
  robot.logger.info logmsg

  notifymsg = "#{who} added `#{entry.val}` to fw #{list_name}."
  if expires isnt 'undefined'
    notifymsg += "  Expires `#{entry.expires}`."
  notifySubscribers notifymsg, who

  # be terse after the first utterance
  fwdata.terse[who] = moment().add(30,'minutes').format()


extendListEntry = (robot, msg) ->
  fullcmd = String(msg.match.shift())
  who = msg.envelope.user.name

  list_name = String(msg.match.shift())
  list_name = 'whitelist' if list_name.indexOf('w') == 0
  list_name = 'blacklist' if list_name.indexOf('b') == 0

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
  for obj in fwdata[list_name] when obj.val.indexOf(l_search) > -1
    #console.log "obj.type: [#{obj.type}] l_search: [#{l_search}] obj.val: [#{obj.val}]"
    if obj.val.indexOf(l_search) > -1
      #console.log "l_search: [#{l_search}] MATCHED obj.val: [#{obj.val}]"
      matches++
      entry = obj
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

  usermsg = "#{who} updated expiration for `#{entry.val}` #{list_name}ing. " +
    "New expiration `#{entry.expires}`."
  msg.reply usermsg

  logmsg = "#{modulename}: robot responded to #{who}: " +
    "updated entry in #{list_name}"
  robot.logger.info logmsg

  #usermsg = usermsg.replace(/  Change will be applied in \< 5 minutes\./, '')
  notifySubscribers usermsg, who


deleteListEntry = (robot, msg) ->
  fullcmd = String(msg.match.shift())
  who = msg.envelope.user.name

  list_name = String(msg.match.shift())
  list_name = 'whitelist' if list_name.indexOf('w') == 0
  list_name = 'blacklist' if list_name.indexOf('b') == 0

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
  deleted.push sprintf displayfmt, 'Type', 'Value', 'Expiration', 'Creator'
  for obj in fwdata[list_name]
    expires = moment(obj.expires)
    if l_type and l_type != obj.type
      new_entry.push obj
      continue
    if l_search and obj.val.indexOf(l_search) == -1
      new_entry.push obj
      continue
    if expires.isBefore() # now
      new_entry.push obj
      continue
    deleted.push sprintf displayfmt, obj.type, obj.val,
      expires.fromNow(), obj.creator

  deltaN = fwdata[list_name].length - new_entry.length
  if deltaN > 0
    usermsg = "#{who} removed `#{deltaN}` fw #{list_name} entries.  " +
      "Change will be applied in < 5 minutes. Removed: " +
      "```"+ deleted.join("\n") + "```"
    fwdata[list_name] = new_entry
    writeData()
  else
    usermsg = "#{list_name} delete request did not match any records."
  msg.reply usermsg

  logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
    "removed #{deltaN} entries from #{list_name}"
  robot.logger.info logmsg

  if deltaN > 0
    #usermsg = usermsg.replace(/  Change will be applied in \< 5 minutes\./, '')
    notifySubscribers usermsg, who


showList = (robot, msg) ->
  list_name = String(msg.match[1])
  list_name = 'whitelist' if list_name.indexOf('w') == 0
  list_name = 'blacklist' if list_name.indexOf('b') == 0

  l_type = false
  l_search = false
  if msg.match[2]?
    l_search = String(msg.match[2])

  logmsg = "#{modulename}: #{msg.envelope.user.name} requested: show #{list_name}"
  robot.logger.info logmsg

  arr = []
  arr.push sprintf displayfmt, 'Type', 'Value', 'Expiration', 'Creator'
  for obj in fwdata[list_name]
    expires = moment(obj.expires)
    if l_type and l_type != obj.type
      continue
    if l_search and obj.val.indexOf(l_search) == -1
      continue
    if expires.isBefore() # now
      continue
    arr.push sprintf displayfmt, obj.type, obj.val, expires.fromNow(), obj.creator

  msg.reply "#{list_name} items and expirations\n```\n"+ arr.join("\n") + "\n```"

  logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
    "displayed #{list_name} items and expirations"
  robot.logger.info logmsg


subscribe = (robot, msg) ->
  user = msg.envelope.user
  who = user.name
  who = msg.match[1] if msg.match[1]

  logmsg = "#{modulename}: #{user.name} requested: notify #{who}"
  robot.logger.info logmsg

  fwdata.notify.push who unless who in fwdata.notify

  usermsg = "Added `#{who}` to firewall change notifications."
  msg.reply usermsg

  logmsg = "#{modulename}: robot responded to #{user.name}: " +
    "added #{who} to firewall change notifications"
  robot.logger.info logmsg

  writeData()


unsubscribe = (robot, msg) ->
  user = msg.envelope.user
  who = msg.envelope.user.name
  who = msg.match[1] if msg.match[1]

  logmsg = "#{modulename}: #{user.name} requested: unnotify #{who}"
  robot.logger.info logmsg

  n = fwdata.notify.indexOf(who)
  fwdata.notify.splice(n, 1) if n > -1

  usermsg = "Removed `#{who}` from firewall change notifications."
  msg.reply usermsg

  logmsg = "#{modulename}: robot responded to #{user.name}: " +
    "removed #{who} from firewall change notifications"
  robot.logger.info logmsg

  writeData()


showSubscribers = (robot, msg) ->
  who = msg.envelope.user.name

  logmsg = "#{modulename}: #{who} requested: subscribers"
  robot.logger.info logmsg

  usermsg = "Subscribers: `"+ fwdata.notify.join('`, `') + "`"
  msg.reply usermsg

  logmsg = "#{modulename}: robot responded to #{who}: " +
    fwdata.notify.join(', ')
  robot.logger.info logmsg


httpGetList = (robot, req, res, list_name, l_type) ->
  clientip = req.connection.remoteAddress || req.socket.remoteAddress ||
    req.connection.socket.remoteAddress

  rememberCheckin clientip, list_name, l_type

  logmsg = "#{modulename}: web request from #{clientip}: get #{l_type} #{list_name}"
  robot.logger.info logmsg

  arr = []
  for obj in fwdata[list_name]
    if obj.type == l_type and moment(obj.expires).isAfter()
      arr.push obj.val
  content = '# nothing here yet! #'
  content = arr.join "\n" if arr.length
  res.setHeader 'content-type', 'text/plain'
  res.end content

  logmsg = "#{modulename}: robot responded to web request: sent #{l_type} #{list_name}"
  robot.logger.info logmsg


showCheckins = (robot, msg) ->
  who = msg.envelope.user.name

  logmsg = "#{modulename}: #{who} requested: checkins"
  robot.logger.info logmsg

  arr = []
  for obj in fwdata.firewalls
    obj.checkin = moment(obj.checkin) if typeof(obj.checkin) is 'string'
    arr.push sprintf '%-18s %-10s %-8s %-15s', obj.name, obj.list, obj.type,
      obj.checkin.fromNow()
  usermsg = "Expect firewall check times: ```"+ arr.join("\n") + "```"
  msg.reply usermsg

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


writeData = ->
  fs.writeFileSync data_file, JSON.stringify(fwdata), 'utf-8'
  logmsg = "#{modulename}: wrote #{data_file}"
  robotRef.logger.info logmsg


module.exports = (robot) ->

  robotRef = robot
  setTimeout expirationWorker, svcQueueIntervalMs

  try
    fwdata = JSON.parse fs.readFileSync data_file, 'utf-8'
    robot.logger.info "#{modulename}: read #{data_file}" if robot.logger
  catch error
    unless error.code is 'ENOENT'
      console.log("#{modulename}: unable to read #{data_file}: ", error)

  robot.router.get "/#{robot.name}/#{modulename}/blacklist/url", (req, res) ->
    return httpGetList robot, req, res, 'blacklist', 'url'

  robot.router.get "/#{robot.name}/#{modulename}/blacklist/cidr", (req, res) ->
    return httpGetList robot, req, res, 'blacklist', 'cidr'

  robot.router.get "/#{robot.name}/#{modulename}/whitelist/url", (req, res) ->
    return httpGetList robot, req, res, 'whitelist', 'url'

  robot.router.get "/#{robot.name}/#{modulename}/whitelist/cidr", (req, res) ->
    return httpGetList robot, req, res, 'whitelist', 'cidr'

  robot.respond /(?:firewall|fw)(?: help| h|)$/, (msg) ->
    who = msg.envelope.user.name
    cmds = ['```']
    arr = [
      modulename + " show (white|black)list [searchterm]"
      modulename + " add (white|black)list <weburl.tld/etc|x.x.x.x> [+7d]"
      modulename + " del (white|black)list <weburl.tld/etc|x.x.x.x>"
      modulename + " extend (white|black)list <weburl.tld/etc|x.x.x.x> [[+-]20d]"
      modulename + " subscribe [username] - subscribe to change notifications"
      modulename + " unsubscribe [username]"
      modulename + " show subscribers"
    ]

    for str in arr
      #cmd = str.split " - "
      #cmds.push "#{cmd[0]} - #{cmd[1]}"
      cmds.push str
    cmds.push '```'

    msg.reply cmds.join "\n"

    logmsg = "#{modulename}: robot responded to #{who}: " +
      "displayed #{modulename} help"
    robot.logger.info logmsg

    return

  robot.respond /(?:firewall|fw) show (?:admins|a)$/i, (msg) ->
    return showAdmins robot, msg

  robot.respond /(?:firewall|fw) show (?:checkins|firewalls|fw|f)$/i, (msg) ->
    return showCheckins robot, msg

  robot.respond /(?:firewall|fw) show (?:subscribers|s)$/i, (msg) ->
    return showSubscribers robot, msg

  robot.respond /(?:firewall|fw) show (whitelist|wl|w|blacklist|bl|b)(?: (.+)|)$/i, (msg) ->
    return showList robot, msg

  robot.respond /(?:firewall|fw) add (whitelist|wl|w|blacklist|bl|b) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    return unless isAuthorized msg
    return unless is2fa msg

    return addListEntry robot, msg

  robot.respond /(?:firewall|fw) (?:delete|del|d) (whitelist|wl|w|blacklist|bl|b) ([^ ]+)$/i, (msg) ->
    return unless isAuthorized msg
    return unless is2fa msg

    return deleteListEntry robot, msg

  robot.respond /(?:firewall|fw) (?:extend|ext|e) (whitelist|wl|w|blacklist|bl|b) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    return unless isAuthorized msg
    return unless is2fa msg

    return extendListEntry robot, msg

  robot.respond /(?:firewall|fw) (?:subscribe|sub)(?: ([^ ]+))$/i, (msg) ->
    return subscribe robot, msg

  robot.respond /(?:firewall|fw) (?:unsubscribe|unsub)(?: ([^ ]+))$/i, (msg) ->
    return unsubscribe robot, msg

