FROM mcr.microsoft.com/dotnet/runtime:8.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Exercise2/Exercise2.csproj", "Exercise2/"]
RUN dotnet restore "Exercise2/Exercise2.csproj"
COPY . .
WORKDIR "/src/Exercise2"
RUN dotnet build "Exercise2.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Exercise2.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Exercise2.dll"]
