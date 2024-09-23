FROM mcr.microsoft.com/dotnet/runtime:8.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Exercise3/Exercise3.csproj", "Exercise3/"]
RUN dotnet restore "Exercise3/Exercise3.csproj"
COPY . .
WORKDIR "/src/Exercise3"
RUN dotnet build "Exercise3.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Exercise3.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Exercise3.dll"]
