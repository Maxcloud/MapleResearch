# MapleStory v95 Client Analysis

Hello everyone welcome to our analysis on GMS v95.1
  - This document is a work in progress
  - This is not a professional document
  - The primary focus is on what I d to do to create localhost
  - There is too much for me to go into excruciating detail about
  - Please contribute if you know anything more !!!


## CSecurityClient
Class used to handle anti cheat integration
  - Houses HackShield related fields in this version
  - In other versions houses NGS and XignCode3 relations fields
  - Is a TSingleton<CSecurityClient>
  
In lots of places in the client usage of CSecurityClient looks like such (pseudo):
```cpp

  if ( TSingleton<CSecurityClient>::IsInstantiated() )
  {
    TSingleton<CSecurityClient>::GetInstance();
    
    //Usage of class such as
    CSecurityClient::InitModule();
  }

```
PatchRetZero here can save you lots of patches you'd have to do in other places otherwise.
##### Class Pseudo

```cpp
// write access to const memory has been detected, the output may be wrong!
void __thiscall CSecurityClient::CSecurityClient(CSecurityClient *this)
{
  CSecurityClient *v1; // edi
  TSecType<int> *v2; // esi
  int v3; // eax
  char v4; // dl
  TSecData<int> *v5; // ecx
  int v6; // eax
  TSecData<int> *v7; // edx
  int v8; // eax
  char v9; // cl

  v1 = this;
  v2 = &this->m_bInitModule;
  if ( this == (CSecurityClient *)-4 )
    TSingleton<CSecurityClient>::ms_pInstance = 0;
  else
    TSingleton<CSecurityClient>::ms_pInstance = this;
  this->vfptr = (CSecurityClientVtbl *)&CSecurityClient::`vftable';
  this->m_bInitModule.m_secdata = (TSecData<int> *)ZAllocEx<ZAllocAnonSelector>::Alloc(
                                                     &ZAllocEx<ZAllocAnonSelector>::_s_alloc,
                                                     0xCu);
  v2->FakePtr1 = (unsigned int)&v2[-1365].FakePtr2 + rand();
  v3 = rand();
  v4 = v2->FakePtr1;
  v5 = v2->m_secdata;
  v2->FakePtr2 = (unsigned int)&v2[-1365].FakePtr2 + v3;
  v5->FakePtr1 = v4;
  v2->m_secdata->FakePtr2 = v2->FakePtr2;
  TSecType<int>::SetData(v2, 0);
  v1->m_bStartModule.m_secdata = (TSecData<int> *)ZAllocEx<ZAllocAnonSelector>::Alloc(
                                                    &ZAllocEx<ZAllocAnonSelector>::_s_alloc,
                                                    0xCu);
  v1->m_bStartModule.FakePtr1 = (unsigned int)&v1[-52].m_szHShieldPath[rand() + 20];
  v6 = rand();
  v7 = v1->m_bStartModule.m_secdata;
  v1->m_bStartModule.FakePtr2 = (unsigned int)&v1[-52].m_szHShieldPath[v6 + 20];
  v7->FakePtr1 = v1->m_bStartModule.FakePtr1;
  v1->m_bStartModule.m_secdata->FakePtr2 = v1->m_bStartModule.FakePtr2;
  TSecType<int>::SetData(&v1->m_bStartModule, 0);
  v1->m_nThreatCode = 0;
  v1->m_nThreatParamSize.m_secdata = (TSecData<long> *)ZAllocEx<ZAllocAnonSelector>::Alloc(
                                                         &ZAllocEx<ZAllocAnonSelector>::_s_alloc,
                                                         0xCu);
  v1->m_nThreatParamSize.FakePtr1 = (unsigned int)&v1[-52].m_szHShieldPath[rand() + 36];
  v8 = rand();
  v9 = v1->m_nThreatParamSize.FakePtr1;
  v1->m_nThreatParamSize.FakePtr2 = (unsigned int)&v1[-52].m_szHShieldPath[v8 + 36];
  v1->m_nThreatParamSize.m_secdata->FakePtr1 = v9;
  v1->m_nThreatParamSize.m_secdata->FakePtr2 = v1->m_nThreatParamSize.FakePtr2;
  TSecType<long>::SetData(&v1->m_nThreatParamSize, 0);
  v1->m_pThreatParam = 0;
  v1->m_hMainWnd = 0;
}
void __thiscall CSecurityClient::InitModule(CSecurityClient *this)
{
  CSecurityClient *v1; // esi
  unsigned int v2; // eax
  int v3; // eax
  int (__stdcall **pExceptionObject)(ZXString<char> *); // [esp+4h] [ebp-214h]
  unsigned int v5; // [esp+8h] [ebp-210h]
  CHAR sModulePath; // [esp+Ch] [ebp-20Ch]
  char v7; // [esp+Dh] [ebp-20Bh]
  unsigned __int8 sModuleFolderPath; // [esp+110h] [ebp-108h]
  char v9; // [esp+111h] [ebp-107h]

  v1 = this;
  sModuleFolderPath = 0;
  memset(&v9, 0, 0x103u);
  sModulePath = 0;
  memset(&v7, 0, 0x103u);
  GetModuleFolderName((char *)&sModuleFolderPath);
  _mbsnbcpy((unsigned __int8 *)&sModulePath, &sModuleFolderPath, 0x104u);
  _mbsnbcat((unsigned __int8 *)&sModulePath, "\\HShield", 8u);
  _mbsnbcpy((unsigned __int8 *)v1->m_szHShieldPath, (const unsigned __int8 *)&sModulePath, 0x104u);
  v2 = _AhnHS_HSUpdateA(&sModulePath, 600000u, 20000u);
  if ( v2 )
  {
    v5 = v2;
    pExceptionObject = CSecurityUpdateFailed::`vftable';
    _CxxThrowException(&pExceptionObject, &_TI2_AVCSecurityUpdateFailed__);
  }
  _mbsnbcpy((unsigned __int8 *)&sModulePath, &sModuleFolderPath, 0x104u);
  _mbsnbcat((unsigned __int8 *)&sModulePath, "\\HShield\\EHSvc.dll", 0x12u);
  v3 = _AhnHS_InitializeA(&sModulePath, (int)_AhnHS_Callback, 9947, (int)"B7621D704ED72C489EE54605", 46808511, 1);
  if ( v3 )
  {
    v5 = v3;
    pExceptionObject = CSecurityInitFailed::`vftable';
    _CxxThrowException(&pExceptionObject, &_TI2_AVCSecurityInitFailed__);
  }
  TSecType<int>::SetData(&v1->m_bInitModule, 1);
}
void __thiscall CSecurityClient::ClearModule(CSecurityClient *this)
{
  TSecType<int> *v1; // esi
  signed int v2; // eax
  int (__stdcall **pExceptionObject)(ZXString<char> *); // [esp+4h] [ebp-8h]
  int v4; // [esp+8h] [ebp-4h]

  v1 = &this->m_bInitModule;
  if ( TSecType<int>::GetData(&this->m_bInitModule) )
  {
    v2 = _AhnHS_Uninitialize();
    if ( v2 )
    {
      v4 = v2;
      pExceptionObject = CSecurityClearFailed::`vftable';
      _CxxThrowException(&pExceptionObject, &_TI2_AVCSecurityClearFailed__);
    }
    TSecType<int>::SetData(v1, 0);
  }
}
void __thiscall CSecurityClient::StartModule(CSecurityClient *this)
{
  CSecurityClient *v1; // esi
  signed int v2; // eax
  int (__stdcall **v3)(ZXString<char> *); // [esp+0h] [ebp-Ch]
  int v4; // [esp+4h] [ebp-8h]

  v1 = this;
  v2 = _AhnHS_StartService();
  if ( v2 )
  {
    v4 = v2;
    v3 = CSecurityInitFailed::`vftable';
    _CxxThrowException(&v3, &_TI2_AVCSecurityInitFailed__);
  }
  _AhnHS_CheckHackShieldRunningStatus();
  v1->m_dwCallbackTime = GetTickCount();
  TSecType<int>::SetData(&v1->m_bStartModule, 1);
}
void __thiscall CSecurityClient::StopModule(CSecurityClient *this)
{
  TSecType<int> *v1; // esi
  signed int v2; // eax
  int (__stdcall **pExceptionObject)(ZXString<char> *); // [esp+4h] [ebp-8h]
  int v4; // [esp+8h] [ebp-4h]

  v1 = &this->m_bStartModule;
  if ( TSecType<int>::GetData(&this->m_bStartModule) )
  {
    v2 = _AhnHS_StopService();
    if ( v2 )
    {
      v4 = v2;
      pExceptionObject = CSecurityClearFailed::`vftable';
      _CxxThrowException(&pExceptionObject, &_TI2_AVCSecurityClearFailed__);
    }
    TSecType<int>::SetData(v1, 0);
  }
}

//Just throws an exception if HS error code is set
//Checks CSecurityClient->m_nThreatCode is a bad HS return code and throw ( result > 0x10501 )
signed int __thiscall CSecurityClient__Update(_DWORD *this)
{
  signed int result; // eax
  bool v2; // zf
  bool v3; // sf
  unsigned __int8 v4; // of
  int (__stdcall **v5)(int); // [esp+0h] [ebp-8h]
  int v6; // [esp+4h] [ebp-4h]

  result = this[7];
  if ( result > 0x10501 )
  {
    if ( result > 0x10801 )
    {
      if ( result != 0x10A01 )
        return result;
LABEL_18:
      v6 = this[7];
      v5 = &off_BF643C;
      sub_A68B61((int)&v5, &_TI2_AVCSecurityThreatDetected__);
      JUMPOUT(*(_DWORD *)algn_A52B42);
    }
    if ( result == 0x10801 || result == 67073 )
      goto LABEL_18;
    if ( result <= 0x10700 )
      return result;
    v4 = __OFSUB__(result, 67333);
    v2 = result == 67333;
    v3 = result - 67333 < 0;
LABEL_10:
    if ( !((unsigned __int8)(v3 ^ v4) | v2) )
      return result;
    goto LABEL_18;
  }
  if ( result == 0x10501 )
    goto LABEL_18;
  if ( result > 0x10303 )
  {
    if ( result < 0x10306 )
      return result;
    v4 = __OFSUB__(result, 66312);
    v2 = result == 66312;
    v3 = result - 66312 < 0;
    goto LABEL_10;
  }
  if ( result >= 0x10301 || result == 0x10102 || result == 0x10104 )
    goto LABEL_18;
  return result;
}
```

## Other Weird Checks

  - Game checks ` ws2_32.dll ` dos header magic to see if its been tampered
  - Game removes loopback adapters ( TODO: Add the winapi call name here )
  - ` GetIpAddrTable GetAdaptersInfo ` calls used to check adapter stuff ?
  - Client checks for the HackShield mutex ` meteora `
  - Client checks to see if ` ehsvc.dll ` is loaded
  - Client literally does an IAT count on the ` ehsvc.dll ` to see if its been tampered. I just loaded original
  - Client checks ` WvsClientMutex ` mutex for multi client

## IP Checks

  - Game is fucking booby trapped with IP checks
  - It's not worth me pointing out where ( will eventually )
  - But basically getpeername is called, just return the expected IP ` 63.251.217.1 `
  - Sad thing is they have heavy API checks on winsock so use the WSP variants like I do
  - TODO: Talk more about the ` MyGetProcAddress ` and heavy winapi checks ( xxxx.nst )

## CWvsApp Checks
  - ` CSecurityClient::Update ` is called in  ` CWvsApp::Run `
  - ` CWvsApp->m_tLastServerIPCheck ` is in ` CWvsApp::CallUpdate `
  - ` CWvsApp->m_tLastServerIPCheck2 ` is in ` CWvsApp::Run `  | Also contains CSecurityClient check below
  - ` CWvsApp->m_tLastSecurityCheck ` is in ` CWvsApp::Run `

#### CWvsApp->m_tLastSecurityCheck
Everyday I pray and ask god what this done but I am unsure. All i know is i have to spoof it so client doesn't crash.

#### CSecurityClient Check
Thisis inside m_tLastServerIPCheck2
Checks if some files in the HShield folder exist `3N.mhe, v3warpds.v3d, v3warpns.v3d `
Checks ` _AhnHS_StartSerice ` ret and expects `HS_ERR_ALREADY_SERVICE_RUNNING` ( 0x00000201 )
Checks `CSecurityClient->m_dwCallbackTime` is ` <= 60000 `

```cpp
    if ( TSingleton_CSecurityClient__IsInstantiated() )
    {
      v22 = '\x01';
      v15 = '3';
      v16 = 'N';
      v17 = '.';
      v18 = 'm';
      v19 = 'h';
      v20 = 'e';
      v21 = '\0';
      v25 = 'v';
      v26 = '3';
      v27 = 'w';
      v28 = 'a';
      v29 = 'r';
      v30 = 'p';
      v31 = 'd';
      v32 = 's';
      v33 = '.';
      v34 = 'v';
      v35 = '3';
      v36 = 'd';
      v37 = '\0';
      v10 = TSingleton_CSecurityClient__GetInstance();
      sub_A6A463(&FileName, "%s\\%s", v10 + 52);
      hObject = CreateFileA(&FileName, 0x40000000u, 0, 0, 3u, 0, 0);
      if ( GetLastError() != 32 )
        v22 = 0;
      if ( hObject != (HANDLE)-1 )
        CloseHandle(hObject);
      if ( _AhnHS_StartService() != 513 )
        v22 = 0;
      v11 = GetTickCount();
      if ( v11 - *(_DWORD *)(TSingleton_CSecurityClient__GetInstance() + 48) > 60000 )
        v22 = 0;
    }
```
Relevant HS callback to above
```cpp

int __stdcall _AhnHS_Callback(int lCode, int lParamSize, void *pParam)
{
  if ( lCode == 65537 )
  {
    if ( TSingleton<CSecurityClient>::ms_pInstance )
    {
      TSingleton<CSecurityClient>::ms_pInstance->m_dwCallbackTime = GetTickCount();
      return 0;
    }
  }
  else if ( TSingleton<CSecurityClient>::ms_pInstance )
  {
    TSingleton<CSecurityClient>::ms_pInstance->m_nThreatCode = lCode;
    TSecType<long>::SetData(&TSingleton<CSecurityClient>::ms_pInstance->m_nThreatParamSize, lParamSize);
    TSingleton<CSecurityClient>::ms_pInstance->m_pThreatParam = pParam;
  }
  return 0;
}

```

## MSCRC
  - ~~I am still trying to figure this out.  Please contribute if you know !!!~~
  - ~~Crc32__GetCrc32~~
  - ~~Crc32__GetCrc32_VMCRC~~
  - ~~Crc32__GetCrc32_VMTABLE~~

  - Click [here](https://github.com/lastbattle/Harepacker-resurrected/commit/814ed0b6b549e7550df17b5a6f5ba8db6964adc5) to view the rebuilt functions. Contribution and special thanks to LastBattle.

## CWvsContext::OnEnterField
Ignore this super shitty pseudo analysis below until I actually solve it. PatchRetZero to skip the call. This MSCRC bypass still used in v200 GMS today. However it skips some game code we need actually need !!! ( Closing UI's and other shit )

```
//Three VM sections in here
void CWvsContext::OnEnterField()
{
//BlaBlaBla

CWvsContext::UI_CloseRevive()

BEGIN_VM_BLOCK

bAuth is a parameter/ret in a MSCRC function (?)

bAuth = 0
var24 = 0
var28 = CClientSocket::SendPacket

Check first byte of CClientSocket::SendPacket against:
(0x55 or 0xB8 or 0x6A )

If check fails: CLIENT_BLOWUP_DEATH


//This mov may have been insert manually
_text:009DBF79 058 C7 45 E8 15 08 45 19                          mov     [ebp+dwThemidaCheckValue], 19450815h

NOPPED CODE I BELIEVE TO THE MSCRC

Compare ebp_dwThemidaCheckValue to the hardcoded value

If check fails: CLIENT_BLOWUP_DEATH

END_VM_BLOCK

CTemporaryStatView::Show(void)
//BlaBlaBla
TSingleton<CRadioManager>::GetInstance(void)

BEGIN_VM_BLOCK
Nopped Shit I need to RE
END_VM_BLOCK

TSingleton<CUIStatusBar>::IsInstantiated(void)
//BlaBlaBla
CField::IsSwimmingMap()

BEGIN_VM_BLOCK
Check value of ` bAuth `
If check fails: CLIENT_BLOWUP_DEATH
END_VM_BLOCK


CTemporaryStatView::Show(void)
//BlaBlaBla
CConfig::SaveSessionInfo_FieldID()
}
====================================================
CLIENT_BLOWUP_DEATH:
_text:009DBF53 058 31 DB                                         xor     ebx, ebx
_text:009DBF55 058 31 D2                                         xor     edx, edx
_text:009DBF57 058 31 F6                                         xor     esi, esi
_text:009DBF59 058 31 FF                                         xor     edi, edi
_text:009DBF5B 058 31 ED                                         xor     ebp, ebp
_text:009DBF5D 058 64 A1 18 00 00 00                             mov     eax, large fs:18h
_text:009DBF63 058 8B 48 08                                      mov     ecx, [eax+8]
_text:009DBF66 058 8B 40 04                                      mov     eax, [eax+4]
_text:009DBF69
_text:009DBF69                                   loc_9DBF69:                             ; CODE XREF: CWvsContext::OnEnterField(void)+B2↓j
_text:009DBF69 058 39 C8                                         cmp     eax, ecx
_text:009DBF6B 058 76 07                                         jbe     short loc_9DBF74
_text:009DBF6D 058 83 E8 04                                      sub     eax, 4
_text:009DBF70 058 89 18                                         mov     [eax], ebx
_text:009DBF72 058 EB F5                                         jmp     short loc_9DBF69
```

## Other Functions

#### DR_check
This function checks for the debug register. PatchRetZero

#### HideDll

This function removes the module from the module list.  This crashes on anything higher than Win7. PatchRetZero

```cpp
void __cdecl HideDll(HINSTANCE__ *hModule)
{
  _LDR_MODULE *pLdrModule; // [esp+0h] [ebp-8h]

  for ( pLdrModule = (_LDR_MODULE *)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList.Flink;
        pLdrModule->BaseAddress && pLdrModule->BaseAddress != hModule;
        pLdrModule = (_LDR_MODULE *)pLdrModule->InLoadOrderModuleList.Flink )
  {
    ;
  }
  if ( pLdrModule->BaseAddress )
  {
    pLdrModule->InLoadOrderModuleList.Blink->Flink = pLdrModule->InLoadOrderModuleList.Flink;
    pLdrModule->InLoadOrderModuleList.Flink->Blink = pLdrModule->InLoadOrderModuleList.Blink;
    pLdrModule->InMemoryOrderModuleList.Blink->Flink = pLdrModule->InMemoryOrderModuleList.Flink;
    pLdrModule->InMemoryOrderModuleList.Flink->Blink = pLdrModule->InMemoryOrderModuleList.Blink;
    pLdrModule->InInitializationOrderModuleList.Blink->Flink = pLdrModule->InInitializationOrderModuleList.Flink;
    pLdrModule->InInitializationOrderModuleList.Flink->Blink = pLdrModule->InInitializationOrderModuleList.Blink;
    pLdrModule->HashTableEntry.Blink->Flink = pLdrModule->HashTableEntry.Flink;
    pLdrModule->HashTableEntry.Flink->Blink = pLdrModule->HashTableEntry.Blink;
    memset(pLdrModule, 0, 0x48u);
  }
}
```

#### SendHSLog

Self explanatory. Called in WinMain. PatchRetZero

```cpp
void __cdecl SendHSLog(unsigned int dwErrCode)
{
  ZXString<char> *v1; // eax
  ZXString<char> result; // [esp+0h] [ebp-314h]
  char szPath[260]; // [esp+4h] [ebp-310h]
  char szHShieldPath[260]; // [esp+108h] [ebp-20Ch]
  char szCharacterName[260]; // [esp+20Ch] [ebp-108h]

  szPath[0] = 0;
  memset(&szPath[1], 0, 0x103u);
  szHShieldPath[0] = 0;
  memset(&szHShieldPath[1], 0, 0x103u);
  szCharacterName[0] = 0;
  memset(&szCharacterName[1], 0, 0x103u);
  GetModuleFileNameA(0, szPath, 0x104u);
  _mbsrchr((const unsigned __int8 *)szPath, 0x5Cu)[1] = 0;
  sprintf(szHShieldPath, "%s\\HShield", szPath);
  v1 = CConfig::GetSessionCharacterName((CConfig *)TSingleton<CConfig>::ms_pInstance._m_pStr, &result);
  sprintf(szCharacterName, "MapleStory_Global:%s", v1->_m_pStr);
  if ( result._m_pStr )
    ZXString<char>::_Release((ZXString<char>::_ZXStringData *)result._m_pStr - 1);
  _AhnHS_SendHsLogA(dwErrCode, (int)szCharacterName, (int)szHShieldPath);
}
```

#### CeTracer::Run

This function sends client crash reports. It makes some reporting window pop up. PatchRetZero

```cpp
void __thiscall CeTracer::Run(CeTracer *this)
{
  if ( this->ET_ErrorCode )
    Start_eTracer(this->ET_ErrorCode, this->ET_MaxErrorCnt);
}
```

## To Do
  - Explain the order of operations / sequence of events
  - ` ZApiLoader `
  - Login IP dynamic initializer `ZInetAddr`
  - MSLoop_Remove();
  - CWvsApp::ConnectLogin(thisa, v5);
  - InitSafeDll_iphdll();
