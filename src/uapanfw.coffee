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
AWS = require 'aws-sdk'
s3 = new AWS.S3()
request = require 'request'
parse = require 'yargs-parser'

modulename = 'fw'
data_file = modulename + ".json"
safety_fail_note = 'If this is time critical ask a human; otherwise please open a ticket.'
displayfmt = '%-4s %-50s %-15s %-10s %s'
timefmt = 'YYYY-MM-DD HH:mm:ss ZZ'
msOneMinute = 60 * 1000
msFiveMinutes = 300 * 1000
glApi = null;
s3bucket = 'ua-oit-security-pub'
s3pathPrefix = 'stats'
defaultNotifyAdmin = 'all' # normally null, for 'all'
defaultNotifySubscribers = 'all' # normally null, for 'all'

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
  hubotAuthAdmin = process.env.HUBOT_AUTH_ADMIN.split ','
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

isAdmin = (msg, reply = true) ->
  console.error 'bad robotRef' unless robotRef
  who = msg.envelope.user.name
  return true if who in hubotAuthAdmin
  msg.reply "This requires administrator privilege." if reply
  return false

isAuthorized = (msg, reply = true) ->
  console.error 'bad robotRef' unless robotRef
  u = msg.envelope.user
  return true if robotRef.auth.hasRole(u,'fw')
  msg.reply "Not authorized.  Missing fw role." if reply
  return false

is2fa = (msg, reply = true) ->
  console.error 'bad robotRef' unless robotRef
  u = msg.envelope.user
  return true if robotRef.auth.is2fa(u)
  msg.reply "2fa required.  Use `auth 2fa` to validate identity." if reply
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

panConfigDevicesVsysRulebaseSecurityRule = (params, callback) ->
  func_name = 'panConfigDevicesVsysRulebaseSecurityRule'
  params = { name: params } if isString params
  return false unless isObject params
  return false unless 'name' of params
  params.path = "/rulebase/security/rules/entry[@name='#{params.name}']"
  return panConfigDevicesVsys params, callback

panConfigDeviceVsysAddress = (params, callback) ->
  func_name = 'panConfigDeviceVsysAddress'
  params = { name: params } if isString params
  return false unless isObject params
  for key in ['name']
    return "#{func_name}: missing required param: #{key}" unless key of param
  params.path = "/address/entry[@name='#{params.name}']"
  return panConfigDevicesVsys params, callback

panConfigDevicesVsys = (params, callback) ->
  func_name = 'panConfigDevicesVsys'
  params = { path: params } if isString params
  return false unless isObject params
  for key in ['path']
    return "#{func_name}: missing required param: #{key}" unless key of param
  params.vsys = 'vsys1' unless 'vsys' of params
  params.path = "/vsys/entry[@name='#{params.vsys}']/#{params.path}"
  return panConfigDevices params, callback

panConfigDevices = (params, callback) ->
  func_name = 'panConfigDevices'
  params = { path: params } if isString params
  return false unless isObject params
  for key in ['path']
    return "#{func_name}: missing required param: #{key}" unless key of param
  params.device = 'localhost.localdomain' unless 'device' of params
  params.path = "/devices/entry[@name='#{params.device}']#{params.path}"
  return panGetConfig params, callback

panConfig = (params, callback) ->
  func_name = 'panConfig'
  return false unless isObject params
  for key in ['fqdn','path','key']
    return "#{func_name}: missing required param: #{key}" unless key of param
  params.action = 'get' unless 'action' of params
  unless params.action in ['get']
    return "#{func_name}: invalid action param: #{params.action}"
  q =
    type: 'config'
    action: params.action
    xpath: "/config#{params.path}"
    key: params.key
  options =
    url: "https://#{params.fqdn}/api/"
    qs: q
    strictSSL: false
    accept: 'text/xml'
  request.get options, (err, res, body) ->
    return callback(null, err) if err
    # XXX: convert xml2json
    return callback(body)
  return true

xmlVal = (name,val) ->
  return '' unless name of obj
  return "<#{name}>#{val}</#{name}>"

panOpTestSecurityPolicyMatch = (params, callback) ->
  func_name = 'panOpTestSecurityPolicyMatch'
  # cmd: <test><security-policy-match><from></from></security-policy-match></test>
  #params = { path: params } if isString params
  cmd = ''
  return false unless isObject params
  required = [
    'destination'
    'destination-port'
    'protocol'
    'source'
  ]
  for key in required
    return "#{func_name}: missing required param: #{key}" unless key of params
    cmd += xmlVal key, params[key]
  optional = [
    'application'
    'category'
    'from'
    'show-all'
    'source-user'
    'to'
  ]
  for key in optional
    if key of params
      cmd += xmlVal key, params[key]
  params.cmd = "<test><security-policy-match>#{cmd}</security-policy-match></test>"
  return panOp params, callback

panCommit = (params, callback) ->
  # cmd: <commit></commit>
  #params = { path: params } if isString params
  cmd = ''
  return false unless isObject params
  params.type = 'commit'
  optional = [
    'description'
  ]
  for name in optional
    if name of params
      cmd += xmlVal name, params[name]
  params.cmd = xmlVal 'commit', cmd
  return panOp params, callback

panOp = (params, callback) ->
  func_name = 'panOp'
  return false unless isObject params
  for key in ['fqdn','cmd']
    return "#{func_name}: missing required param: #{key}" unless key of param
  param.type = 'op' unless 'type' of params
  unless params.type in ['op','commit']
    return "#{func_name}: invalid param type: #{params.type}" 
  q =
    type: 'op'
    cmd: params.cmd
  options =
    url: "https://#{params.fqdn}/api/"
    qs: q
    strictSSL: false
    accept: 'text/xml'
  request.get options, (err, res, body) ->
    return callback(null, err) if err
    # XXX: convert xml2json
    return callback(body)
  return true


oneMinuteWorker = ->
  queryAndProcessAttacks()
  setTimeout oneMinuteWorker, msOneMinute


fiveMinuteWorker = ->
  for list in ['autoban','blacklist','whitelist']
    uploadReport list, 'all', 'list'
    for type in ['url','cidr','domain']
      continue if list is 'autoban' and type isnt 'cidr'
      uploadReport list, type, 'terse'
  expireAttackers()
  preExpireNotify 'blacklist'
  preExpireNotify 'whitelist'
  expireEntriesFromList 'blacklist'
  expireEntriesFromList 'whitelist'
  expireEntriesFromList 'autoban'
  setTimeout fiveMinuteWorker, msFiveMinutes


queryAndProcessCommits = ->
  func_name = 'queryAndProcessCommits'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  console.log "#{log_date} #{func_name} --"
  return if glApi is null
  q =
    query: 'logfile:SYSTEM\/general',
    fields: 'message,source',
    range: 60,
    decorate: 'true'
  glApi.query q
  #console.log 'exec glApi.get() with glApi.options: ', JSON.stringify glApi.options, null, 2
  glApi.get() (err, res, body) ->
    unless res.statusCode is 200
      return console.warn 'Error requesting Graylog url statusCode=', res.statusCode, 'err=', err, 'options=', glApi.options
    glresponse = JSON.parse body
    #console.log 'glApi returns body:', JSON.stringify jsonbody, null, 2
    events = glresponse.messages.map (m) => m.message
    for event in events
      processCommit event

queryAndProcessAttacks = ->
  func_name = 'queryAndProcessAttacks'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  console.log "#{log_date} #{func_name} --"
  return if glApi is null
  q =
    query: 'logfile:THREAT\\/vulnerability',
    fields: 'message,source,addrsrc,addrdst,action',
    range: 60,
    decorate: 'true'
  glApi.query q
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
    list: list_name
    created: moment().format()
    expires: attackSource.banexpires
    type: 'cidr'
    val: attackSource.attacker
    reason: "#{attackSource.attacks} attacks\n#{msgs}"
  result = addListEntry entry
  if result isnt true
    usermsg = "Failed to add `#{entry.val}` (#{entry.type}) to list" +
      " #{list_name}.  Error: `#{result}`"
    notifySubscribers list_name, usermsg
  
  #notifymsg = "#{entry.creator} added `#{entry.val}` (#{entry.type}) to list"
  #notifymsg += " #{list_name}. Expires `#{entry.expires}`."
  #notifySubscribers list_name, notifymsg


uploadReport = (list_name, list_type, list_style) ->
  func_name = 'uploadReport'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  params =
    type: list_type
  r = buildList list_name, params
  s3upload "#{list_name}-#{list_type}-#{list_style}", r[list_style]


s3upload = (filename,body,type='plain') ->
  func_name = 's3upload'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  params =
    Bucket: s3bucket
    Key: "#{s3pathPrefix}/#{filename}"
    ContentType: "text/#{type}"
    Body: body
  s3.putObject params, (err, data) ->
    if err
      return console.error "#{log_date} #{func_name}: #{err}"
    console.log "#{log_date} #{func_name}: #{params.ContentType} #{params.Bucket}:#{params.Key} success"


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

  dt_hour_from_now = moment().add(1,'hours')
  params =
    expires: 'before'
    when: dt_hour_from_now
  r = buildList list_name, params
  return unless r.lines > 0
  expiring = r.list

  usermsg = "fw: #{list_name} entries will expire soon: " +
    "```#{expiring}```"
  notifySubscribers list_name, usermsg


expireEntriesFromList = (list_name) ->
  func_name = 'expireEntriesFromList'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')

  unless list_name of fwdata.lists
    return console.error "#{log_date} #{func_name}: #{list_name} does not exist"

  dt_now = moment()
  params =
    expires: 'before'
    when: dt_now
  r = buildList list_name, params
  return unless r.lines > 0
  deleted = r.list

  removequeue = []
  list = fwdata.lists[list_name]
  for entry in list when moment(entry.expires).isBefore(dt_now)
    removequeue.push entry

  while removequeue.length > 0
    entry = removequeue.shift()
    list.splice(list.indexOf(entry), 1)
  usermsg = "fw: #{list_name} entries expired and have been removed: " +
    "```#{deleted}```"
  notifySubscribers list_name, usermsg
  writeData()


notifySubscribers = (list_name, usermsg, current_un = false, who = defaultNotifySubscribers) ->
  func_name = 'notifySubscribers'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  return console.error "#{log_date} #{func_name}: bad robotRef" unless robotRef
  return console.error "#{log_date} #{func_name}: bad list: #{list_name}" unless list_name in list_names
  return console.error "#{log_date} #{func_name}: list not created: #{list_name}" unless list_name of fwdata.notify
  return console.error "#{log_date} #{func_name}: list empty: #{list_name}" unless isArray fwdata.notify[list_name]
  un_list = who if isArray who
  un_list = [who] if isString who
  un_list = fwdata.notify[list_name] if who == 'all' or who is null
  return notifyUsers usermsg, current_un, un_list


notifyUsers = (usermsg, current_un = false, who = null) ->
  func_name = 'notifyUsers'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  return console.error "#{log_date} #{func_name}: bad robotRef" unless robotRef
  return console.error "#{log_date} #{func_name}: must specify who" if who is null
  un_list = who if isArray who
  un_list = [who] if isString who
  for un in un_list
    console.log "#{log_date} #{func_name} #{un}: #{usermsg}"
    robotRef.send { room: un }, usermsg unless current_un && un == current_un
  return un_list


notifyAdmins = (usermsg, current_un = false, who = defaultNotifyAdmin) ->
  func_name = 'notifyAdmins'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  return console.error "#{log_date} #{func_name}: bad robotRef" unless robotRef
  un_list = who if isArray who
  un_list = [who] if isString who
  un_list = hubotAuthAdmin if who == 'all' or who is null
  for un in un_list when un.indexOf('U') != 0
    console.log "#{log_date} #{func_name} #{un}: #{usermsg}"
    robotRef.send { room: un }, usermsg unless current_un && un == current_un
  return un_list


showAdmins = (robot, msg) ->
  fullcmd = String msg.match.shift()
  who = msg.envelope.user.name

  logmsg = "#{modulename}: #{who} requested: #{fullcmd}"
  robot.logger.info logmsg

  msg.reply "#{modulename} admins: #{hubotAuthAdmin.join(', ')}"

  logmsg = "#{modulename}: robot responded to #{who}: " +
    "provided list of admins"
  robot.logger.info logmsg


ruleAddEntryHelp = (robot, msg) ->
  func_name = 'ruleAddEntryHelp'
  who = msg.envelope.user.name
  arr = [
    "#{modulename} rule <options>"
    ""
    "Required options:"
    "  -N, --name    Rule name"
    "  -f, --from    From zone, eg. Untrust"
    "  -t, --to      To zone, e.g. DMZ"
    "  -s, --src     Source address"
    "  -d, --dst     Dest address"
    "  -S, --svc     Service, e.g. service-http"
    "  -a, --app     Application, e.g. web-browse"
    "  -e, --erd     URL to Firewall Access Diagram"
    ""
    "Note: if rule name already exists, this will replace it!"
  ]
  output = arr.join "\n"
  msg.send "```#{output}```"
  robot.logger.info "#{modulename}: #{func_name}: #{who}: displayed help"


ruleAddEntry = (robot, msg) ->
  func_name = 'ruleAddEntry'
  fullcmd = String msg.match.shift()
  who = msg.envelope.user.name

  robot.logger.info "#{modulename}_#{func_name}: #{who}: #{fullcmd}"

  cmd = String msg.match.shift()
  return ruleAddEntryHelp(robot,msg) if cmd is 'undefined'
  args = parse cmd
  args = {} unless isObject args
  console.log "cmd: #{cmd} out: #{JSON.stringify args}"
  return ruleAddEntryHelp(robot,msg) if 'h' of args
  return ruleAddEntryHelp(robot,msg) if 'help' of args
  return unless is2fa msg

  keys =
    N: 'name'
    f: 'from'
    t: 'to'
    s: 'src'
    d: 'dst'
    S: 'svc'
    a: 'app'
    e: 'erd'
  for key of keys
    if key of args
      args[ keys[key] ] = args[key]
      delete args[key]

  args.requestor = who
  result = processRule args, who
  unless result is true
    errmsg = "Unable to submit request"
    errmsg += ":```#{result}```" unless result is false
    return msg.send errmsg

  msg.send "Submitted rule for review!"


normType = (val) ->
  return val.join ", " if isArray val
  return val if isString val
  return "unable to handle value"


normHttpPrefix = (val) ->
  if val.toLowerCase().indexOf('http://') == 0
    return val.replace(/http:\/\//i,'')
  return val


processRule = (rule, who) ->
  func_name = 'processRule'
  return false unless isObject rule
  required = [
    'requestor'
    'src'
    'dst'
    'name'
    'erd'
  ]
  for name in required
    return "#{func_name}: missing required parameter: #{name}" unless name of rule
  unless 'app' of rule or 'svc' of rule
    return "#{func_name}: missing required parameter: app or svc"

  # convert single values to array
  for key in ['from','to','src','dst','app','svc']
    continue unless key of rule # skip if not present
    rule[key] = [ rule[key] ] unless isArray rule[key]

  # check zones
  # XXX: check against zone names

  # check addresses
  # XXX: check against address and address-group objects
  
  # remove slack url prefixes from fqdn style object names
  for key in ['src','dst']
    newarray = []
    for val in rule[key]
      newarray.push normHttpPrefix val
    rule[key] = newarray

  # check app
  # XXX: check against app names

  # check svc
  # XXX: check against service and service-group objects

  # add or update request queue
  dt_now = moment()
  req =
    id: "#{who[0..2]}#{dt_now.format('MMDDHHmmss')}"
    by: who
    type: 'rule'
    when: dt_now.format()
    request: rule
  addUpdateRequestEntry req
  return true


addUpdateRequestEntry = (req) ->
  return false unless isObject req
  return false unless 'id' of req
  usermsg = markupRequest req
  notifiedAdmins = notifyAdmins usermsg
  notifyUsers usermsg, false, req.by unless req.by in notifiedAdmins

  fwdata.requests[req.id] = req
  writeData()
  return true


deleteRequestEntry = (req, res) ->
  return false unless isObject req
  return false unless isObject res
  return false unless 'id' of req
  usermsg = markupRequest req, res
  notifiedAdmins = notifyAdmins usermsg
  notifyUsers usermsg, false, req.by unless req.by in notifiedAdmins

  delete fwdata.requests[req.id]
  writeData()
  return true


markupRequest = (req, res = null) ->
  type = req.type[0].toUpperCase() + req.type[1..-1].toLowerCase()
  adminmsg = "#{type} requested by #{req.by}."
  if res
    adminmsg = "#{type} #{res.action} by #{res.by}."
    adminmsg += "\n> *Comment* #{res.comment}" if 'comment' of res
  adminmsg += "\nRequest metadata:"
  for key of req
    continue if key in ['request','type']
    adminmsg += "\n> *#{key}* #{req[key]}"
  adminmsg += "\nRequest:"
  entry = req.request
  for key of entry
    adminmsg += "\n> *#{key}* #{entry[key]}"
  return adminmsg


requestQueue_NotifyAdmin_list = (entry, who, comment = null, action = 'requested', notifyList = null) ->
  adminmsg = "List #{action} by #{who}."
  adminmsg += "\n> *Comment* #{comment}" unless comment is null
  for key of entry
    adminmsg += "\n> *#{key}* #{entry[key]}"
  #adminmsg += "> *Name* #{entry.name}"
  #adminmsg += "\n> *Value* #{normType entry.val}"
  #adminmsg += "\n> *Type* #{normType entry.type}"
  #adminmsg += "\n> *Expires* #{normType entry.expires}"
  notifyAdmins adminmsg, false, notifyList


helperListName = (list_name) ->
  return false unless isString list_name
  return false unless list_name.length > 0
  return 'whitelist' if list_name.indexOf('w') == 0
  return 'blacklist' if list_name.indexOf('b') == 0
  return 'autoban'   if list_name.indexOf('a') == 0
  if list_name of fwdata.lists
    return list_name
  return false

listAddEntryHelp = (robot, msg) ->
  func_name = 'listAddEntryHelp'
  who = msg.envelope.user.name
  arr = [
    "#{modulename} list add -L <list> -i|-d|-u <value> [options]"
    ""
    "Required options:"
    "  -L <list>        List name; e.g. blacklist"
    "  -i <ip or cidr>  Address or cidr entry, e.g. 127.0.0.1/8"
    "  -d <domain>      Domain entry, e.g. example.com"
    "  -u <url>         URL entry, e.g. example.com/phishing/page123"
    ""
    "Optional:"
    "  -e <date>        Expiration, e.g. +12h, +30d, +6m, +1y, 2021-10-21"
    "  -r               Request; required if not authorized and 2fa enabled"
    "  -R <reason>      Reason for entry, e.g. \"SR 12345\""
  ]
  output = arr.join "\n"
  msg.send "```#{output}```"
  robot.logger.info "#{modulename}_#{func_name}: #{who}: displayed help"


listAddEntry = (robot, msg) ->
  func_name = 'listAddEntry'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  fullcmd = String msg.match[0]
  who = msg.envelope.user.name

  cmd = String msg.match[1]
  return listAddEntryHelp(robot,msg) if cmd is 'undefined'
  args = parse cmd
  args = {} unless isObject args
  console.log "#{log_date} #{func_name}: cmd: #{cmd} out: #{JSON.stringify args}"
  return listAddEntryHelp(robot,msg) if 'h' of args
  return listAddEntryHelp(robot,msg) if 'help' of args

  entry =
    creator: who
    created: moment().format()
    expires: moment().add(1, 'months').format()

  unless 'L' of args
    return msg.send "#{func_name}: must specify `-L <list>`"
  entry.list = helperListName args['L']
  unless entry.list
    return msg.send "#{func_name}: invalid list: #{args['L']}"

  if 'i' of args
    addrs = false
    if isArray args.i
      addrs = args.i
    if isString args.i
      addrs = [args.i]
      addrs = args.i.split(',') if args.i.indexOf(',') > 0
    if addrs is false
      usermsg = "#{func_name}: invalid ip-address or cidr"
      logmsg = "#{modulename}: #{who} request failed: #{usermsg}"
      robot.logger.info logmsg
      return msg.send usermsg
    for addr in addrs
      if extra = addr.match /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})((?:\/\d{1,2}|))$/
        if extra[2] isnt '' and extra[2] > -1 and extra[2] < 16
          usermsg = "#{func_name}: Blocking addresses with cidr less than /16 not allowed."
          logmsg = "#{modulename}_#{func_name}: #{who} request failed: #{usermsg}"
          robot.logger.info logmsg
          msg.send usermsg unless isAdmin msg, false # no redundant admin notifications
          return notifyAdmins logmsg
      else
        usermsg = "#{func_name}: invalid ip-address or cidr"
        logmsg = "#{modulename}_#{func_name}: #{who} request failed: #{usermsg}"
        robot.logger.info logmsg
        return msg.send usermsg
      if UA_Network.contains addr
        usermsg = "Blocking addresses in the UA_Network is not allowed. #{safety_fail_note}"
        logmsg = "#{modulename}_#{func_name}: #{who} request failed safety check: #{fullcmd}"
        robot.logger.info logmsg
        msg.send usermsg unless isAdmin msg, false # no redundant admin notifications
        return notifyAdmins "#{logmsg}\nReason: #{usermsg}"
    entry.type = 'cidr'
    entry.val = addrs[0] if addrs.length == 1
    entry.vals = addrs if addrs.length > 1

  if 'd' of args
    domain = normHttpPrefix args.d
    for arr in preventDomainBlacklist when domain.toLowerCase().match arr[1]
      usermsg = "Blocking `#{arr[0]}` is not allowed. #{safety_fail_note}"
      logmsg = "#{modulename}: #{who} request failed safety check: #{fullcmd}"
      robot.logger.info logmsg
      msg.send usermsg
      return notifyAdmins "#{logmsg}\nReason: #{usermsg}"
    entry.type = 'domain'
    entry.val = domain

  if 'u' of args
    url = normHttpPrefix args.u
    if url.toLowerCase().indexOf('https://') == 0
      return msg.send "#{entry.list}ing of https links not supported."
    for arr in preventUrlBlacklist when url.toLowerCase().match arr[1]
      usermsg = "Blocking `#{arr[0]}` is not allowed. #{safety_fail_note}"
      logmsg = "#{modulename}: #{who} request failed safety check: #{fullcmd}"
      robot.logger.info logmsg
      msg.send usermsg
      return notifyAdmins "#{logmsg}\nReason: #{usermsg}"
    entry.type = 'url'
    entry.val = url

  unless 'type' of entry
    return msg.send "#{modulename}_#{func_name}: must specify `-i <ip>`, `-d <domain>`, or `-u <url>`"

  if 'e' of args
    expires = args.e
    if extra = expires.match /\+(\d+)([a-zA-Z]+)/
      n = extra[1]
      unit = extra[2]
      unless unit in ['h','hours','d','days','w','weeks','M','months','Q','quarters','y','years']
        usermsg = "Invalid unit `#{unit}` in expiration `#{expires}`. Use h or hours, d or days, w or weeks, M or months, Q or quarters, y or years."
        return msg.send usermsg
      entry.expires = moment().add(n,unit).format()
    else if moment(expires).isValid()
      entry.expires = moment(expires).format()
    else
      usermsg = "invalid expiration date: #{expires}"
      return msg.send usermsg

  # reason
  if 'R' of args
    entry.reason = args['R']

  # request
  if 'r' of args
    dt_now = moment()
    req =
      id: "#{who[0..2]}#{dt_now.format('MMDDHHmmss')}"
      by: who
      type: 'list'
      when: dt_now.format()
      request: entry
    addUpdateRequestEntry req
    return msg.send "Queued request for review!"

  unless isAuthorized msg
    usermsg = "or specify `-r` to request listing"
    logmsg = "#{modulename}: #{who} listing failed: #{usermsg}"
    robot.logger.info logmsg
    return msg.send usermsg
  unless is2fa msg
    usermsg = "or specify `-r` to request listing"
    logmsg = "#{modulename}: #{who} listing failed: #{usermsg}"
    robot.logger.info logmsg
    return msg.send usermsg

  result = addListEntry entry
  if result isnt true
    usermsg = "Failed to add to list #{entry.list}. Error: `#{result}`"
    msg.send usermsg

  usermsg = ''
  usermsg += "#{entry.creator} added `#{entry.val}` (#{entry.type}) to *#{entry.list}*." if 'val' of entry
  if 'vals' of entry
    usermsg += "#{entry.creator} added *#{entry.vals.length}* #{entry.type} entries to *#{entry.list}*."
    usermsg += "```#{entry.vals.join ', '}```"
  usermsg += "  Expires #{entry.expires}." if expires isnt 'undefined'
  usermsg += "  Reason: ```#{entry.reason}```" if 'reason' of entry
  notifySubscribers entry.list, usermsg, who
  usermsg += "  Change will be applied in < 5 minutes." unless isTerse who
  msg.send usermsg

  logmsg = "#{modulename}: robot responded to #{who}: "
  logmsg += "added entry to #{entry.list}" if 'val' of entry
  logmsg += "added #{entry.vals.length} entries to #{entry.list}" if 'vals' of entry
  robot.logger.info logmsg

  # be terse after the first utterance
  fwdata.terse[who] = moment().add(30,'minutes').format()


addListEntry = (entry) ->
  func_name = 'addListEntry'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')

  vals = false
  console.log "#{JSON.stringify entry}"

  # validate correct list_name
  return "parameter not object" unless isObject entry
  return "must specify: list"     unless 'list' of entry
  return "must specify: creator"  unless 'creator' or entry
  return "must specify: created"  unless 'created' of entry
  return "must specify: type"     unless 'type' of entry
  return "must specify: expires"  unless 'expires' of entry
  vals = [entry.val] if 'val' of entry
  vals = entry.vals if 'vals' of entry
  return "must specify: val or vals" if vals is false
  return "invalid list #{entry.list}" unless entry.list in list_names

  logmsg = "#{modulename}_#{func_name}: #{entry.creator} requested:"
  logmsg += " #{entry.list} #{entry.type} #{entry.val}" if 'val' of entry
  logmsg += " #{entry.list} #{entry.type} #{entry.vals.length} entries" if 'vals' of entry
  logmsg += " expires #{moment(entry.expires).format(timefmt)}"
  logmsg += " reason #{entry.reason}" if 'reason' of entry
  robotRef.logger.info logmsg

  fwdata.lists[entry.list] = [] unless entry.list of fwdata.lists

  for val in vals
    e =
      creator: entry.creator
      created: entry.created
      expires: entry.expires
      list: entry.list
      type: entry.type
      val: val
    e.reason = entry.reason if 'reason' of entry
    logmsg = "#{modulename}_#{func_name}: #{e.creator} added"
    logmsg += " #{e.list} #{e.type} #{e.val}"
    logmsg += " expires #{moment(e.expires).fromNow()}"
    logmsg += " reason #{e.reason}" if 'reason' of e
    robotRef.logger.info logmsg
    fwdata.lists[entry.list].push e

  writeData()

  return true


listExtendEntryHelp = (robot, msg) ->
  func_name = 'listExtendEntryHelp'
  who = msg.envelope.user.name
  arr = [
    "#{modulename} list extend -L <list> -s <searchstring> -e <expiration>"
    ""
    "Required options:"
    "  -L    List name; e.g. blacklist"
    "  -s    Search string, must only match one entry; e.g. 127.0.0.1"
    "  -e    Expiration, e.g. -12h, +36h, -1d, +30d, +6m, +1y, 2021-10-21, etc"
  ]
  output = arr.join "\n"
  msg.send "```#{output}```"
  robot.logger.info "#{modulename}: #{func_name}: #{who}: displayed help"


listExtendEntry = (robot, msg) ->
  func_name = 'listExtendEntry'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  fullcmd = String msg.match[0]
  who = msg.envelope.user.name

  robot.logger.info "#{modulename}: #{func_name}: #{who}: #{fullcmd}"

  cmd = String msg.match[1]
  return listExtendEntryHelp(robot,msg) if cmd is 'undefined'
  args = parse cmd
  args = {} unless isObject args
  return listExtendEntryHelp(robot,msg) if 'h' of args
  return listExtendEntryHelp(robot,msg) if 'help' of args

  unless 'L' of args
    return msg.send "#{func_name}: must specify `-L <list>`"
  list_name = helperListName args['L']
  unless list_name
    return msg.send "#{func_name}: invalid list: #{args['L']}"
  
  unless 's' of args
    return msg.send "#{func_name}: must specify `-s <searchstring>`"
  l_search = args.s

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

  unless 'e' of args
    usermsg = "you must provide a new absolute or relative expiration"
    return msg.reply usermsg

  expires = args.e
  if extra = expires.match /(-|\+|)(\d+)([a-zA-Z])/
    direction = extra.shift()
    n = extra.shift()
    unit = extra.shift()
    unless unit in ['h','hours','d','days','w','weeks','M','months','Q','quarters','y','years']
      usermsg = "Invalid unit `#{unit}` in expiration `#{expires}`. Use h or hours, d or days, w or weeks, M or months, Q or quarters, y or years."
      return msg.send usermsg
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
    return msg.send usermsg

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


listDeleteEntryHelp = (robot, msg) ->
  func_name = 'listDeleteEntryHelp'
  who = msg.envelope.user.name
  arr = [
    "#{modulename} list delete -L <list> -s|-i|-d|-u <value> [options]"
    ""
    "Required options:"
    "  -L <list>        List name; e.g. blacklist"
    "  -i <ip or cidr>  Address or cidr entry, e.g. 127.0.0.1/8"
    "  -d <domain>      Domain entry, e.g. example.com"
    "  -u <url>         URL entry, e.g. example.com/phishing/page123"
    ""
    "Optional:"
    "  -r               Request; required if not authorized and 2fa enabled"
  ]
  output = arr.join "\n"
  msg.send "```#{output}```"
  robot.logger.info "#{modulename}_#{func_name}: #{who}: displayed help"


listDeleteEntry = (robot, msg) ->
  func_name = 'listDeleteEntry'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  fullcmd = String msg.match[0]
  who = msg.envelope.user.name

  robot.logger.info "#{modulename}_#{func_name} #{who} requested: #{fullcmd}"

  cmd = String msg.match[1]
  return listDeleteEntryHelp(robot,msg) if cmd is 'undefined'
  args = parse cmd
  args = {} unless isObject args
  return listDeleteEntryHelp(robot,msg) if 'h' of args
  return listDeleteEntryHelp(robot,msg) if 'help' of args

  q =
    axis: 0

  unless 'L' of args
    return msg.send "#{func_name}: must specify `-L <list>`"

  q.list = helperListName args['L']
  unless q.list
    return msg.send "#{func_name}: invalid list: #{q.list}"
  
  required = 0
  if 's' of args
    required++
    q.search = args.s
    if q.search.toLowerCase().indexOf('https://') == 0
      return msg.reply "https links not supported"
    if args.s.toLowerCase().indexOf('http://') == 0
      q.search = args.s.replace(/http:\/\//i,'')
    q.axis += 1

  if 'i' of args
    required++
    addrs = false
    if isArray args.i
      addrs = args.i
    if isString args.i
      addrs = [args.i]
      addrs = args.i.split(',') if args.i.indexOf(',') > 0
    if addrs is false
      usermsg = "#{func_name}: invalid ip-address or cidr"
      logmsg = "#{modulename}: #{who} request failed: #{usermsg}"
      robot.logger.info logmsg
      return msg.send usermsg
    q.axis += 2
    q.type = 'cidr'
    q.addrs = addrs

  # display help unless one of the rquired parameter is specified
  return listDeleteEntryHelp(robot,msg) unless required > 0

  searched = 0
  deleted = []
  new_listdata = []
  listdata = fwdata.lists[q.list]
  deleted.push sprintf displayfmt, 'Type', 'Value', 'Expiration', 'Creator', 'Reason'
  for e in listdata
    axis = 0
    #console.log "#{log_date} #{func_name}: #{JSON.stringify e}"
    # if not a match, add it to the keepers
    if 'type' of q
      test = q.type == e.type
      #console.log "#{log_date} #{func_name}: TYPE e.type|#{e.type} == q.type|#{q.type} = test|#{test}"
      if test
        axis++
        #console.log "#{log_date} #{func_name}: incremented axis: #{axis}"
    if 'search' of q
      test = e.val.indexOf(q.search) == -1
      #console.log "#{log_date} #{func_name}: SEARCH e.val|#{e.val} q.search|#{q.search} test|#{test}"
      if test
        axis++
        #console.log "#{log_date} #{func_name}: incremented axis: #{axis}"
    if 'addrs' of q
      test = e.val in q.addrs
      #console.log "#{log_date} #{func_name}: ADDRS e.val|#{e.val} q.addrs|#{q.addrs} test|#{test}"
      if test
        axis++
        #console.log "#{log_date} #{func_name}: incremented axis: #{axis}"
    if axis < q.axis
      #console.log "#{log_date} #{func_name}: axis|#{axis} < q.axis|#{q.axis} = NOT ENOUGH AXIS, keeping entry"
      new_listdata.push e
      continue
    #console.log "#{log_date} #{func_name}: axis|#{axis} >= q.axis|#{q.axis} = ENOUGH AXIS, deleting entry"

    expires = moment(e.expires)
    #if expires.isBefore() # now
    #  new_listdata.push e
    #  continue

    # display
    reason = ''
    if 'reason' of e
      unless e.reason.indexOf("\n") > 0
        reason = e.reason
      else
        reason = e.reason.split("\n").shift().substring(0,20)
    deleted.push sprintf displayfmt, e.type, e.val,
      expires.fromNow(), e.creator, reason

  deltaN = listdata.length - new_listdata.length
  if deltaN > 0
    usermsg = "#{who} removed *#{deltaN}* entries from *#{q.list}*"
    usermsg += "```"+ deleted.join("\n") + "```"
    fwdata.lists[q.list] = new_listdata
    writeData()
  else
    usermsg = "#{q.list} delete request did not match any records."
  msg.send usermsg

  logmsg = "#{modulename}_#{func_name} #{who} response: " +
    "removed #{deltaN} entries from #{q.list}"
  robot.logger.info logmsg

  if deltaN > 0
    notifySubscribers q.list, usermsg, who


listShow = (robot, msg) ->
  func_name = 'listShow'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  fullcmd = String msg.match[0]
  who = msg.envelope.user.name

  robot.logger.info "#{modulename}_#{func_name} #{who} requested: #{fullcmd}"

  list_name = String(msg.match[1])
  list_name = 'whitelist' if list_name.indexOf('w') == 0
  list_name = 'blacklist' if list_name.indexOf('b') == 0
  list_name = 'autoban' if list_name.indexOf('a') == 0

  l_type = false
  l_search = false
  if msg.match[2]?
    l_search = String(msg.match[2])

  unless list_name of fwdata.lists and fwdata.lists[list_name].length > 0
    return msg.send "No entries on list #{list_name}."

  params = {}
  params.type = l_type if l_type
  params.search = l_search if l_search
  r = buildList list_name, params
  
  maxLinesViaChat = 10
  if r.lines == 1
    msg.send r.single
  if r.lines > 1 and r.lines <= maxLinesViaChat
    msg.send "*#{list_name}* #{r.lines} entries.\n```#{r.list}```"
  if r.lines > maxLinesViaChat
    msg.send "*#{list_name}* #{r.lines} entries.\n"+
      ">List too long to display through chat. Try this:\n"+
      ">https://s3-us-west-2.amazonaws.com/"+
      "#{s3bucket}/#{s3pathPrefix}/#{list_name}-all-list"

  logmsg = "#{modulename}: #{func_name}: robot responded to #{msg.envelope.user.name}: " +
    "displayed #{list_name} items and expirations"
  robot.logger.info logmsg


requestShowHelp = (robot, msg) ->
  func_name = 'requestShowHelp'
  who = msg.envelope.user.name
  arr = [
    "#{modulename} request show -a|-i <id>|-n <name>|-t <type>"
    ""
    "Options:"
    "  -a    All requests"
    "  -i    Request id"
    "  -n    Requestor name"
    "  -t    Request type"
  ]
  output = arr.join "\n"
  msg.send "```#{output}```"
  robot.logger.info "#{modulename}: #{func_name}: #{who}: displayed help"


requestShow = (robot, msg) ->
  func_name = 'requestShow'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  fullcmd = String msg.match[0]
  who = msg.envelope.user.name

  robot.logger.info "#{modulename}: #{func_name}: #{who}: #{fullcmd}"

  cmd = String msg.match[1]
  return requestShowHelp(robot,msg) if cmd is 'undefined'
  args = parse cmd
  args = {} unless isObject args
  return requestShowHelp(robot,msg) if 'h' of args
  return requestShowHelp(robot,msg) if 'help' of args

  if 'i' of args
    unless args.i of fwdata.requests
      msg.send "#{func_name}: request does not exist: id=#{args.i}"
    usermsg = markupRequest fwdata.requests[args.i]
    msg.send usermsg
    logmsg = "#{modulename}: #{func_name}: responded to #{who}: " +
      "displaying id #{args.i}"
    return robot.logger.info logmsg

  out = ''
  requestCount = 0
  for key of fwdata.requests
    req = fwdata.requests[key]
    continue if 'u' of args and req.by isnt args.u
    continue if 't' of args and req.type isnt args.t
    requestCount += 1
    out += "type=#{req.type} id=#{req.id} by=#{req.by} when=#{req.when}\n"
  
  if requestCount > 0
    msg.send "Requests:\n```#{out}```"
  else
    msg.send "No requests in queue; nice work!"

  logmsg = "#{modulename}: #{func_name}: responded to #{who}: " +
    "displayed #{requestCount} requests"
  robot.logger.info logmsg


requestApproveHelp = (robot, msg) ->
  func_name = 'requestApproveHelp'
  who = msg.envelope.user.name
  arr = [
    "#{modulename} request approve -i <id> -m \"<message>\""
    ""
    "Required options:"
    "  -i    Request id"
    "  -m    Approval message"
    ""
    "Note: immediate upon approval the request will be applied!"
  ]
  output = arr.join "\n"
  msg.send "```#{output}```"
  robot.logger.info "#{modulename}: #{func_name}: #{who}: displayed help"


requestApprove = (robot, msg) ->
  func_name = 'requestApprove'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  fullcmd = String msg.match[0]
  who = msg.envelope.user.name

  robot.logger.info "#{modulename}: #{func_name}: #{who}: #{fullcmd}"

  cmd = String msg.match[1]
  return requestDeclineHelp(robot,msg) if cmd is 'undefined'
  args = parse cmd
  args = {} unless isObject args
  return requestDeclineHelp(robot,msg) if 'h' of args
  return requestDeclineHelp(robot,msg) if 'help' of args
  console.log "#{log_date} #{func_name}: cmd: #{cmd} out: #{JSON.stringify args}"
  return unless is2fa msg

  unless 'i' of args
    return msg.send "#{func_name}: missing required parameter: `-i <id>`"
  id = args.i

  unless 'm' of args
    return msg.send "#{func_name}: missing required parameter: `-m \"<msg>\"`"
  message = args.m

  unless id of fwdata.requests
    return msg.send "#{func_name}: request not found: id=#{id}"

  req = fwdata.requests[id]

  result = false
  if req.type is 'list'
    result = addListEntry(req.request)
  else
    result = "unable to process request type: #{req.type}"

  unless result is true
    return msg.send "Failed to apply #{req.type}.  Error: ```#{result}```"

  res =
    by: who
    action: 'approved'
    comment: args.m
  deleteRequestEntry req, res

  #msg.send "Request #{id} approved with message: ```#{message}```"

  logmsg = "#{modulename}: #{func_name}: responded to #{who}: " +
    "request #{id} approved with message: #{message}"
  robot.logger.info logmsg


requestDeclineHelp = (robot, msg) ->
  func_name = 'requestDeclineHelp'
  who = msg.envelope.user.name
  arr = [
    "#{modulename} request decline -i <id> -m <message>"
    ""
    "Required options:"
    "  -i    Request id"
    "  -m    Decline message"
    ""
    "Note: immediate upon decline the request is removed and notification sent."
  ]
  output = arr.join "\n"
  msg.send "```#{output}```"
  robot.logger.info "#{modulename}: #{func_name}: #{who}: displayed help"


requestDecline = (robot, msg) ->
  func_name = 'requestDecline'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')
  fullcmd = String msg.match[0]
  who = msg.envelope.user.name

  robot.logger.info "#{modulename}_#{func_name}: #{who}: #{fullcmd}"

  cmd = String msg.match[1]
  return requestDeclineHelp(robot,msg) if cmd is 'undefined'
  args = parse cmd
  args = {} unless isObject args
  return requestDeclineHelp(robot,msg) if 'h' of args
  return requestDeclineHelp(robot,msg) if 'help' of args
  console.log "#{log_date} #{func_name}: cmd: #{cmd} out: #{JSON.stringify args}"
  return unless is2fa msg

  unless 'i' of args
    return msg.send "#{func_name}: missing required parameter: `-i <id>`"
  id = args.i

  unless 'm' of args
    return msg.send "#{func_name}: missing required parameter: `-m \"<msg>\"`"
  message = args.m

  unless id of fwdata.requests
    return msg.send "#{func_name}: request not found: id=#{id}"

  req = fwdata.requests[id]
  res =
    by: who
    action: 'declined'
    comment: args.m
  deleteRequestEntry req, res

  #msg.send "Request #{id} declined with message: ```#{message}```"

  logmsg = "#{modulename}: #{func_name}: responded to #{who}: " +
    "request #{id} declined with message: #{message}"
  robot.logger.info logmsg


buildList = (list_name, params = {}) ->
  func_name = 'buildList'
  log_date = moment().format('YYYY-MM-DD HH:mm:ss')

  lines = 0 # entries
  out_terse = '' # string
  delete params.type if 'type' of params and params.type is 'all'
  out_list = sprintf "#{displayfmt}\n", 'Type', 'Value', 'Expiration', 'Creator', 'Reason'
  for e in fwdata.lists[list_name]
    bool_expires = false
    dt_expires = moment(e.expires)
    if 'expires' of params
      dt = moment() unless 'when' of params
      dt = moment(params.when) if 'when' of params
      bool_expires = dt_expires.isBefore(dt)
      bool_expires = dt_expires.isBefore(dt) if params.expires == 'before' and dt_expires.isBefore(dt)
      bool_expires = dt_expires.isAfter(dt)  if params.expires == 'after'  and dt_expires.isAfter(dt)
      #console.log "#{log_date} #{func_name} #{dt_expires.fromNow()} / #{dt_expires.format()} #{params.expires} #{dt.format()} #{bool_expires}"
      continue unless bool_expires
    else
      continue if dt_expires.isBefore() # skip expired
    continue if 'type' of params and params.type != e.type
    continue if 'search' of params and e.val.indexOf(params.search) == -1
    reason = ''
    reason = e.reason if 'reason' of e
    if reason.indexOf("\n") > 0
      reason = e.reason.split("\n").shift().substring(0,20)
    vals = [e.val] if 'val' of e
    vals = e.vals if 'vals' of e
    for val in vals
      lines++
      out_terse += "#{val}\n"
      out_list += sprintf "#{displayfmt}\n", e.type, val, dt_expires.fromNow(), e.creator, reason
      out_single = "#{e.creator} added `#{val}` (#{e.type}) to list"
      out_single += " #{list_name}. Expires #{moment(e.expires).fromNow()}."
      out_single += " Reason: ```#{e.reason}```" if 'reason' of e
  output =
    single: out_single
    terse: out_terse
    list: out_list
    lines: lines
  return output


listSubscribe = (robot, msg) ->
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

  usermsg = "Added #{who} to list #{list_name}."
  msg.send usermsg

  logmsg = "#{modulename}: robot responded to #{user.name}: " +
    "added #{who} to list #{list_name}"
  robot.logger.info logmsg

  writeData()


listUnsubscribe = (robot, msg) ->
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

  usermsg = "Removed #{who} from list #{list_name}."
  msg.send usermsg

  logmsg = "#{modulename}: robot responded to #{user.name}: " +
    "removed #{who} from list #{list_name}"
  robot.logger.info logmsg

  writeData()


listShowSubscribers = (robot, msg) ->
  func_name = 'listShowSubscribers'
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

  params =
    type: list_type
  r = buildList list_name, params

  content = '# nothing here yet! #'
  content = r.terse if r.lines > 0
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
  admin = isAdmin msg
  arr = [
    "#{modulename} list show <list> [searchterm]"
    "#{modulename} list add -h"
    "#{modulename} list del -h"
    "#{modulename} list extend -h"
    "#{modulename} list subscribe <list> [username] - subscribe to change notifications"
    "#{modulename} list unsubscribe <list> [username]"
    "#{modulename} list subscribers [list]"
    "#{modulename} rule <options>"
  ]
  arr.push "#{modulename} request show [options]" if admin
  arr.push "#{modulename} request approve <options>" if admin

  out = arr.join "\n"
  msg.send "```#{out}```"

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
  else
    console.warn "#{modulename}: HUBOT_GRAYLOG_URL and HUBOT_GRAYLOG_TOKEN" +
      " environment variables not set."
  setTimeout oneMinuteWorker, 5 * 1000
  setTimeout fiveMinuteWorker, 15 * 1000

  try
    fwdata = JSON.parse fs.readFileSync data_file, 'utf-8'
    robot.logger.info "#{modulename}: read #{data_file}" if robot.logger
    fwdata =              {} unless isObject fwdata
    fwdata['notify'] =    {} unless isObject fwdata['notify']
    fwdata['lists'] =     {} unless isObject fwdata['lists']
    fwdata['firewalls'] = [] unless isArray  fwdata['firewalls']
    fwdata['terse'] =     {} unless isObject fwdata['terse']
    fwdata['attackers'] = {} unless isObject fwdata['attackers']
    fwdata['requests'] =  {} unless isObject fwdata['requests']
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

  robot.respond /(?:firewall|fw) list show (?:admins)$/i, (msg) ->
    return showAdmins robot, msg

  robot.respond /(?:firewall|fw) list show (?:checkins|firewalls|fw)$/i, (msg) ->
    return showCheckins robot, msg

  robot.respond /(?:firewall|fw) list subscribers(?: (.+)|)$/i, (msg) ->
    return listShowSubscribers robot, msg

  robot.respond /(?:firewall|fw) list show ([^ ]+)(?: (.+)|)$/i, (msg) ->
    return listShow robot, msg

  robot.respond /(?:firewall|fw) list (?:add|a)(?: (.+)|)$/i, (msg) ->
    return listAddEntry robot, msg

  robot.respond /(?:firewall|fw) list (?:delete|del|d)(?: (.+)|)$/i, (msg) ->
    return unless isAuthorized msg
    return unless is2fa msg

    return listDeleteEntry robot, msg

  robot.respond /(?:firewall|fw) list (?:extend|ext|e) ([^ ]+) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    return unless isAuthorized msg
    return unless is2fa msg

    return listExtendEntry robot, msg

  robot.respond /(?:firewall|fw) list (?:subscribe|sub) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    return listSubscribe robot, msg

  robot.respond /(?:firewall|fw) list (?:unsubscribe|unsub) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    return listUnsubscribe robot, msg

  robot.respond /(?:firewall|fw) (?:rule|r)(?: (.+)|)$/i, (msg) ->
    return unless isAuthorized msg
    return ruleAddEntry robot, msg

  robot.respond /(?:firewall|fw) (?:request|req) show(?: (.+)|)$/i, (msg) ->
    return unless isAdmin msg
    return requestShow robot, msg

  robot.respond /(?:firewall|fw) (?:request|req) (?:approve|app|a)(?: (.+)|)$/i, (msg) ->
    return unless isAdmin msg
    return requestApprove robot, msg

  robot.respond /(?:firewall|fw) (?:request|req) (?:decline|dec|d)(?: (.+)|)$/i, (msg) ->
    return unless isAdmin msg
    return requestDecline robot, msg

