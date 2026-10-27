window.LabExamples={
  before:{schemaVersion:'1.0',kind:'windows-image-audit',capturedAt:'2026-01-01T00:00:00Z',source:'simulated',machine:{os:'Windows 11 Pro · EJEMPLO',name:'VM-DEMO'},controls:[
    {id:'firewall',status:'pass',observed:'Perfiles activos · ejemplo'},
    {id:'inbound',status:'fail',observed:'Una entrada permitida · ejemplo'},
    {id:'guest',status:'pass',observed:'Invitado deshabilitado · ejemplo'},
    {id:'admin',status:'fail',observed:'Administrador integrado activo · ejemplo'},
    {id:'rdp',status:'fail',observed:'RDP habilitado sin necesidad · ejemplo'},
    {id:'winrm',status:'pass',observed:'WinRM deshabilitado · ejemplo'},
    {id:'sshd',status:'pass',observed:'sshd ausente · ejemplo'},
    {id:'bitlocker',status:'fail',observed:'Volumen sin protección · ejemplo'},
    {id:'updates',status:'unknown',observed:'Consulta no disponible · ejemplo'}]},
  after:{schemaVersion:'1.0',kind:'windows-image-audit',capturedAt:'2026-01-02T00:00:00Z',source:'simulated',machine:{os:'Windows 11 Pro · EJEMPLO',name:'VM-DEMO'},controls:[
    {id:'firewall',status:'pass',observed:'Perfiles activos · ejemplo'},
    {id:'inbound',status:'pass',observed:'Entrada bloqueada · ejemplo'},
    {id:'guest',status:'pass',observed:'Invitado deshabilitado · ejemplo'},
    {id:'admin',status:'pass',observed:'Administrador integrado deshabilitado · ejemplo'},
    {id:'rdp',status:'pass',observed:'RDP deshabilitado · ejemplo'},
    {id:'winrm',status:'pass',observed:'WinRM deshabilitado · ejemplo'},
    {id:'sshd',status:'pass',observed:'sshd ausente · ejemplo'},
    {id:'bitlocker',status:'fail',observed:'Volumen sin protección · ejemplo'},
    {id:'updates',status:'unknown',observed:'Consulta no disponible · ejemplo'}]}
};
for(const [name,profile,services,ports,users,features,rules] of [
  ['before','por_defecto',['EventLog','WinRM','Spooler','wuauserv'],[135,139,445],[{nombre:'LabAdmin',habilitado:true},{nombre:'Estudiante',habilitado:true},{nombre:'Invitado',habilitado:true}],['SMB1Protocol','NetFx3','MediaPlayback'],12],
  ['after','endurecida',['EventLog','wuauserv','Spooler'],[135],[{nombre:'LabAdmin',habilitado:true},{nombre:'Estudiante',habilitado:true},{nombre:'Invitado',habilitado:false}],['NetFx3','MediaPlayback'],7]
]){const a=window.LabExamples[name];a.perfil=profile;a.profile=profile;a.equipo=a.machine.name;a.fecha=a.capturedAt;a.servicios_en_ejecucion=services;a.puertos_escuchando=ports;a.usuarios_locales=users;a.firewall=[{perfil:'Private',activo:true,entrada:'Block'}];a.caracteristicas_opcionales=features;a.exposure={tcpListeningPorts:ports,inboundAllowRules:rules,note:'Ejemplo simulado; no representa una VM.'};}
