(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.LabCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const controls = [
    { id: 'firewall', title: 'Firewall activo en todos los perfiles', why: 'Reduce conexiones entrantes no solicitadas.', fix: 'Active Domain, Private y Public; revise excepciones antes de aplicar.' },
    { id: 'inbound', title: 'Entrada predeterminada bloqueada', why: 'Obliga a justificar cada excepción entrante.', fix: 'Use bloqueo por defecto y permita solo servicios necesarios.' },
    { id: 'guest', title: 'Cuenta Invitado deshabilitada', why: 'Evita una cuenta local innecesaria.', fix: 'Deshabilite Guest si no se utiliza.' },
    { id: 'admin', title: 'Administrador integrado deshabilitado', why: 'Reduce un objetivo conocido de autenticación.', fix: 'Mantenga otra cuenta administradora comprobada antes de deshabilitarlo.' },
    { id: 'rdp', title: 'RDP deshabilitado si no se necesita', why: 'Elimina un servicio remoto opcional.', fix: 'Deshabilite RDP solo desde consola local y documente la excepción.' },
    { id: 'winrm', title: 'WinRM deshabilitado si no se necesita', why: 'Elimina la administración remota innecesaria.', fix: 'Detenga WinRM solo si no forma parte de la administración prevista.' },
    { id: 'sshd', title: 'Servidor OpenSSH deshabilitado si no se necesita', why: 'Evita una superficie SSH entrante.', fix: 'Deshabilite sshd si no existe un caso de uso.' },
    { id: 'bitlocker', title: 'Volumen del sistema protegido', why: 'Protege datos si se pierde la máquina o el disco.', fix: 'Verifique TPM, edición y resguardo de la clave de recuperación antes de activarlo.' },
    { id: 'updates', title: 'Actualizaciones automáticas disponibles', why: 'Facilita recibir correcciones de seguridad.', fix: 'Mantenga Windows Update habilitado y compruebe su política real.' }
  ];
  function escapeXml(s) { return String(s).replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&apos;'}[c])); }
  function normalizeAudit(input) {
    if (!input || input.schemaVersion !== '1.0' || input.kind !== 'windows-image-audit' || !Array.isArray(input.controls)) throw new Error('JSON incompatible: se requiere schemaVersion 1.0, kind windows-image-audit y controls[].');
    if (!input.capturedAt || !input.machine || !input.machine.os) throw new Error('Faltan fecha o datos del sistema.');
    if (!['measured','simulated'].includes(input.source)) throw new Error('El origen debe ser measured o simulated.');
    if (!['por_defecto','endurecida'].includes(input.profile)) throw new Error('Falta el perfil: por_defecto o endurecida.');
    if (input.perfil !== input.profile) throw new Error('El campo perfil debe coincidir con profile.');
    for(const key of ['servicios_en_ejecucion','puertos_escuchando','usuarios_locales','firewall','caracteristicas_opcionales'])if(input[key]!==null&&!Array.isArray(input[key]))throw new Error('Campo de medición inválido: '+key);
    const ids = new Set();
    const normalized = input.controls.map(c => {
      if (!c || typeof c.id !== 'string' || ids.has(c.id) || !controls.some(x => x.id === c.id)) throw new Error('Control desconocido o duplicado.');
      ids.add(c.id);
      if (!['pass','fail','na','unknown'].includes(c.status)) throw new Error('Estado inválido en ' + c.id);
      return { id:c.id, status:c.status, observed:String(c.observed || ''), reason:String(c.reason || '') };
    });
    if (ids.size !== controls.length) throw new Error('El archivo debe contener los nueve controles.');
    let exposure=null;
    if(input.exposure){const x=input.exposure;if(x.tcpListeningPorts!==null&&(!Array.isArray(x.tcpListeningPorts)||!x.tcpListeningPorts.every(n=>Number.isInteger(n)&&n>=0&&n<=65535)))throw new Error('Puertos de exposición inválidos.');if(x.inboundAllowRules!==null&&(!Number.isInteger(x.inboundAllowRules)||x.inboundAllowRules<0))throw new Error('Conteo de reglas inválido.');exposure={tcpListeningPorts:x.tcpListeningPorts??null,inboundAllowRules:x.inboundAllowRules??null,note:String(x.note||'')};}
    return { schemaVersion:'1.0', kind:'windows-image-audit', capturedAt:String(input.capturedAt), source:input.source, perfil:input.perfil, profile:input.profile, machine:{ os:String(input.machine.os), name:String(input.machine.name || '') }, controls:normalized, exposure, servicios_en_ejecucion:input.servicios_en_ejecucion??null, puertos_escuchando:input.puertos_escuchando??null, usuarios_locales:input.usuarios_locales??null, firewall:input.firewall??null, caracteristicas_opcionales:input.caracteristicas_opcionales??null };
  }
  function score(audit) {
    const applicable = audit.controls.filter(c => c.status === 'pass' || c.status === 'fail');
    const passed = applicable.filter(c => c.status === 'pass').length;
    return { passed, applicable:applicable.length, value:applicable.length ? Math.round(100*passed/applicable.length) : null, unknown:audit.controls.filter(c => c.status === 'unknown').length };
  }
  function compare(before, after) {
    return controls.map(meta => {
      const a = before.controls.find(c => c.id === meta.id), b = after.controls.find(c => c.id === meta.id);
      return { ...meta, before:a.status, after:b.status, change:a.status === b.status ? 'same' : a.status === 'fail' && b.status === 'pass' ? 'improved' : a.status === 'pass' && b.status === 'fail' ? 'regressed' : 'scope-changed' };
    });
  }
  function surface(a){return {services:a.servicios_en_ejecucion?.length??null,ports:a.puertos_escuchando?.length??null,users:a.usuarios_locales?.filter(u=>u.habilitado===true).length??null,features:a.caracteristicas_opcionales?.length??null,allowRules:a.exposure?.inboundAllowRules??null};}
  function surfaceChanges(b,a){const defs=[['Servicios',b.servicios_en_ejecucion,a.servicios_en_ejecucion],['Puertos TCP',b.puertos_escuchando,a.puertos_escuchando],['Cuentas habilitadas',b.usuarios_locales?.filter(u=>u.habilitado).map(u=>u.nombre),a.usuarios_locales?.filter(u=>u.habilitado).map(u=>u.nombre)],['Características',b.caracteristicas_opcionales,a.caracteristicas_opcionales]];return defs.map(([label,before,after])=>({label,removed:before&&after?before.filter(x=>!after.includes(x)):null,added:before&&after?after.filter(x=>!before.includes(x)):null}));}
  function generateUnattend(options) {
    const locale = String(options.locale || 'es-CR');
    if (!/^[a-z]{2,3}-[A-Z]{2}$/.test(locale)) throw new Error('Idioma inválido. Use un código como es-CR.');
    const timezone = String(options.timezone || 'Central America Standard Time');
    if (!/^[A-Za-z0-9 _/+\-]{1,80}$/.test(timezone)) throw new Error('Zona horaria inválida.');
    const name = String(options.computerName || '*').trim().toUpperCase();
    if (name !== '*' && !/^[A-Z0-9][A-Z0-9-]{0,14}$/.test(name)) throw new Error('Nombre de equipo inválido: máximo 15 caracteres, letras, números y guion.');
    const arch = options.arch === 'arm64' ? 'arm64' : 'amd64';
    const e = escapeXml;
    const protect = options.declineExpress === false ? '1' : '3';
    return `<?xml version="1.0" encoding="utf-8"?>\n<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">\n  <settings pass="oobeSystem">\n    <component name="Microsoft-Windows-International-Core" processorArchitecture="${arch}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">\n      <InputLocale>${e(locale)}</InputLocale><SystemLocale>${e(locale)}</SystemLocale><UILanguage>${e(locale)}</UILanguage><UserLocale>${e(locale)}</UserLocale>\n    </component>\n    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="${arch}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">\n      <ComputerName>${e(name)}</ComputerName><TimeZone>${e(timezone)}</TimeZone>\n      <OOBE><HideEULAPage>false</HideEULAPage><ProtectYourPC>${protect}</ProtectYourPC></OOBE>\n    </component>\n  </settings>\n</unattend>\n`;
  }
  function generateAutounattend(o) {
    const user=String(o.userName||'').trim();
    if(!/^[A-Za-z][A-Za-z0-9_-]{1,18}$/.test(user)||user.toLowerCase()==='labadmin')throw new Error('Usuario estándar inválido: 2–19 caracteres, empezando con una letra; no use LabAdmin.');
    const pass=String(o.tempPassword||''), adminPass=String(o.adminPassword||'');
    if(!/^[A-Za-z0-9!@#$%*_-]{20,64}$/.test(pass)||!/^[A-Za-z0-9!@#$%*_-]{20,64}$/.test(adminPass))throw new Error('Faltan contraseñas temporales generadas de forma segura.');
    if(o.wipeDisk!==true||o.acceptEula!==true)throw new Error('La instalación automática requiere marcar el disco exclusivo de la VM y aceptar los términos tras revisarlos.');
    const index=Number(o.imageIndex);if(!Number.isInteger(index)||index<1||index>50)throw new Error('Índice de imagen inválido.');
    const base=generateUnattend(o);
    const arch=o.arch==='arm64'?'arm64':'amd64', e=escapeXml;
    const account=`<UserAccounts><LocalAccounts><LocalAccount wcm:action="add"><Name>${e(user)}</Name><DisplayName>${e(user)}</DisplayName><Group>Users</Group><Password><Value>${e(pass)}</Value><PlainText>true</PlainText></Password></LocalAccount><LocalAccount wcm:action="add"><Name>LabAdmin</Name><DisplayName>LabAdmin</DisplayName><Group>Administrators</Group><Password><Value>${e(adminPass)}</Value><PlainText>true</PlainText></Password></LocalAccount></LocalAccounts></UserAccounts>`;
    const setup=`  <settings pass="windowsPE">\n    <component name="Microsoft-Windows-Setup" processorArchitecture="${arch}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">\n      <DiskConfiguration><Disk wcm:action="add"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk><CreatePartitions><CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>300</Size></CreatePartition><CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition><CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition></CreatePartitions><ModifyPartitions><ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition><ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label></ModifyPartition></ModifyPartitions></Disk><WillShowUI>OnError</WillShowUI></DiskConfiguration>\n      <ImageInstall><OSImage><InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>${index}</Value></MetaData></InstallFrom><InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo><WillShowUI>OnError</WillShowUI></OSImage></ImageInstall>\n      <UserData><AcceptEula>true</AcceptEula></UserData>\n    </component>\n  </settings>\n`;
    return base.replace('  <settings pass="oobeSystem">',setup+'  <settings pass="oobeSystem">').replace('<OOBE><HideEULAPage>false</HideEULAPage>',account+'\n      <OOBE><HideEULAPage>true</HideEULAPage>');
  }
  return { controls, normalizeAudit, score, compare, surface, surfaceChanges, generateUnattend, generateAutounattend };
});
