FROM mcr.microsoft.com/dotnet/framework/sdk:4.8-windowsservercore-ltsc2022 AS build
WORKDIR /app

#Copy everything and build app
COPY ./src/mysimplewebapp/ .
RUN msbuild ./mysimplewebapp.sln -t:Restore /p:Configuration=Release

FROM mcr.microsoft.com/dotnet/framework/aspnet:4.8-windowsservercore-ltsc2022 AS runtime
SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

#Install the necessary IIS components
RUN Install-WindowsFeature Web-Server; \
Install-WindowsFeature Web-Asp-Net45; \
Install-WindowsFeature Web-Net-Ext45;

WORKDIR /inetpub/wwroot/#{ENVIRONMENT}#

#Create the App Pool
RUN Import-Module IISAdministration; \
New-IISAppPool -Name 'MySimpleWebAppPool'; \
Set-ItemProperty -Path 'IIS:\AppPools\MySimpleWebAppPool' -Name processModel.identityType -Value 'LocalSystem';

#Create the Site Configuration
RUN New-IISSite -Name 'MySimpleWebApp' -PhysicalPath 'C:\inetpub\wwwroot' -BindingInformation '*:80:' -ApplicationPool 'MySimpleWebAppPool'; \
Set-ItemProperty -Path 'IIS:\Sites\MySimpleWebApp' -Name bindings[0].protocol -Value 'http';

#Copy the built app to the IIS site
COPY --from=build /app .

#Assign the built app to the Site Configuration
RUN Import-Module WebAdministration; \
Set-WebConfigurationProperty -Filter 'system.applicationHost/sites/site[@name="MySimpleWebApp"]/application[@path="/"]' -Name 'applicationPool' -Value 'MySimpleWebAppPool'; \
Set-WebConfigurationProperty -Filter 'system.webServer/defaultDocument' -Name 'enabled' -Value 'True'; \
Set-WebConfigurationProperty -Filter 'system.webServer/defaultDocument' -Name 'files' -Value @{path='Default.htm,Default.asp,index.htm,index.html,iisstart.htm,default.aspx'}; 

#Start the IIS service
RUN Start-Service W3SVC;

#Expose port 80 to allow web traffic to flow in
EXPOSE 80

#Run the application
CMD ["ping", "localhost"]




