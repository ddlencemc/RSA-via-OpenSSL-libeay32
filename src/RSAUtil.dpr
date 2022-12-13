program RSAUtil;

uses
  Forms,
  Unit1 in 'Unit1.pas' {Form1},
  RSAOpenSSL in 'RSAOpenSSL.pas';

{$R *.res}

begin

  ReportMemoryLeaksOnShutdown := DebugHook <> 0;

  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
