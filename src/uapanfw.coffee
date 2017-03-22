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
sprintf = require("sprintf-js").sprintf

modulename = 'fw'
fwdata_file = modulename + ".json"
displayfmt = '%-4s %-50s %-15s %s'
timefmt = 'YYYY-MM-DD HH:mm:ss ZZ'
svcQueueIntervalMs = 300 * 1000

robotRef = false
fwdata =
  notify: []
  blacklist: []
  whitelist: []
  firewalls: []

fwnames =
  '10.9.0.252': 'Fairbanks-1'
  '10.9.0.253': 'Fairbanks-2'
  '10.9.128.252': 'Anchorage-1'
  '10.9.128.253': 'Anchorage-2'
  '10.9.192.252': 'Juneau-1'
  '10.9.192.253': 'Juneau-2'

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


expirationWorker = ->
  expireEntriesFromList 'blacklist'
  expireEntriesFromList 'whitelist'
  setTimeout expirationWorker, svcQueueIntervalMs


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
    msg = "fw: #{list_name} entries expired and have been removed. " +
      "Change will be applied in < 5 minutes. Removed: " +
      "```"+ deleted.join("\n") + "```"
    notifySubscribers msg
    fs.writeFileSync fwdata_file, JSON.stringify(fwdata), 'utf-8'

notifySubscribers = (msg, current_un = false) ->
  console.error 'bad robotRef' unless robotRef
  for un in fwdata.notify
    robotRef.send { room: un }, msg unless current_un && un == current_un

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
  #console.log list_name

  l_val = String(msg.match.shift())
  if extra = l_val.match /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2}|))$/
    entry.type = 'cidr'
    entry.val = extra[1]

    # safety check !!
    if entry.val.match /^(?:137\.229\.|199\.165\.)/
      usermsg = "Blocking CIDRs begining with 137.229. or 199.165. not allowed. "+
        " If this is time critical ask a human for help; otherwise open a ticket."
      return msg.reply usermsg

  else if extra = l_val.match /^([a-zA-Z][a-zA-Z0-9\.]+)$/
    entry.type = 'domain'
    entry.val = extra[1]

    # safety check !!
    if entry.val.toLowerCase().match /(?:alaska|uaf)\.edu$/
      usermsg = "Blocking alaska.edu or uaf.edu not allowed. "+
        " If this is time critical ask a human for help; otherwise open a ticket."
      return msg.reply usermsg

  else
    entry.type = 'url'
    entry.val = l_val
    if entry.val.toLowerCase().indexOf('https://') == 0
      usermsg = "#{list_name}ing of https links not supported."
      return msg.reply usermsg
    if entry.val.toLowerCase().indexOf('http://') == 0
      entry.val = entry.val.replace(/http:\/\//i,'')

    # safety check !!
    if entry.val.toLowerCase().match /[^\/]+(?:alaska|uaf)\.edu/
      usermsg = "Blocking alaska.edu or uaf.edu not allowed. "+
        " If this is time critical ask a human for help; otherwise open a ticket."
      return msg.reply usermsg

  #console.log "#{l_val}: #{entry.type} => #{entry.val}"

  expires = String(msg.match.shift())
  if expires isnt 'undefined'
    #console.log "processing expiration: #{expires}"
    extra = expires.match /\+(\d)([hdwMQy])/
    if extra?
      n = extra[1]
      unit = extra[2]
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
  fs.writeFileSync fwdata_file, JSON.stringify(fwdata), 'utf-8'

  usermsg = "#{who} added `#{entry.val}` to firewall #{list_name}. " +
    "Expires `#{entry.expires}`.  Change will be applied in < 5 minutes."
  msg.reply usermsg

  logmsg = "#{modulename}: robot responded to #{who}: " +
    "added entry to #{list_name}"
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
      errfmt = 'type: [%s] != [%s]'
      #console.log sprintf errfmt, l_type, obj.type
      new_entry.push obj
      continue
    if l_search and obj.val.indexOf(l_search) == -1
      errfmt = 'search: indexOf[%s] not found in [%s]'
      #console.log sprintf errfmt, l_search, obj.val
      new_entry.push obj
      continue
    if expires.isBefore() # now
      #console.log 'expires: ['+ expires +'] is before now'
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
    fs.writeFileSync fwdata_file, JSON.stringify(fwdata), 'utf-8'
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
      #console.log 'skipping type: '+ obj.type
      continue
    if l_search and obj.val.indexOf(l_search) == -1
      #console.log 'skipping search: '+ obj.val
      continue
    if expires.isBefore() # now
      #console.log 'skipping expires: '+ obj.expires
      continue
    #console.log 'adding to array: '
    #console.log obj
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

  fs.writeFileSync fwdata_file, JSON.stringify(fwdata), 'utf-8'


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

  fs.writeFileSync fwdata_file, JSON.stringify(fwdata), 'utf-8'


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
      fs.writeFileSync fwdata_file, JSON.stringify(fwdata), 'utf-8'
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
  fs.writeFileSync fwdata_file, JSON.stringify(fwdata), 'utf-8'

module.exports = (robot) ->

  robotRef = robot
  setTimeout expirationWorker, svcQueueIntervalMs

  try
    fwdata = JSON.parse fs.readFileSync fwdata_file, 'utf-8'
  catch error
    console.log('Unable to read file', error) unless error.code is 'ENOENT'

  robot.router.get "/#{robot.name}/#{modulename}/blacklist/url", (req, res) ->
    return httpGetList robot, req, res, 'blacklist', 'url'

  robot.router.get "/#{robot.name}/#{modulename}/blacklist/cidr", (req, res) ->
    return httpGetList robot, req, res, 'blacklist', 'cidr'

  robot.router.get "/#{robot.name}/#{modulename}/whitelist/url", (req, res) ->
    return httpGetList robot, req, res, 'whitelist', 'url'

  robot.router.get "/#{robot.name}/#{modulename}/whitelist/cidr", (req, res) ->
    return httpGetList robot, req, res, 'whitelist', 'cidr'

  robot.respond /(?:firewall|fw)(?: help| h|)$/, (msg) ->
    cmds = ['```']
    arr = [
      modulename + " show (white|black)list [searchterm]"
      modulename + " add (white|black)list <weburl.tld/etc|x.x.x.x>"
      modulename + " del (white|black)list <weburl.tld/etc|x.x.x.x>"
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

    logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
      "displayed #{modulename} help"
    robot.logger.info logmsg

    return

  robot.respond /(?:firewall|fw) show (?:checkins)$/i, (msg) ->
    return showCheckins robot, msg

  robot.respond /(?:firewall|fw) show (?:subscribers|s)$/i, (msg) ->
    return showSubscribers robot, msg

  robot.respond /(?:firewall|fw) show (whitelist|wl|w|blacklist|bl|b)(?: (.+)|)$/i, (msg) ->
    return showList robot, msg

  robot.respond /(?:firewall|fw) add (whitelist|wl|w|blacklist|bl|b) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    return unless isAuthorized msg
    return unless is2fa msg

    return addListEntry robot, msg

  robot.respond /(?:firewall|fw) (?:delete|del|d) (whitelist|wl|w|blacklist|bl|b) (url|cidr) ([^ ]+)$/i, (msg) ->
    return unless isAuthorized msg
    return unless is2fa msg

    return deleteListEntry robot, msg

  robot.respond /(?:firewall|fw) (?:subscribe|sub)(?: ([^ ]+))$/i, (msg) ->
    return subscribe robot, msg

  robot.respond /(?:firewall|fw) (?:unsubscribe|unsub)(?: ([^ ]+))$/i, (msg) ->
    return unsubscribe robot, msg

