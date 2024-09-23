FROM mcr.microsoft.com/dotnet/runtime:8.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Exercise1/Exercise1.csproj", "Exercise1/"]
RUN dotnet restore "Exercise1/Exercise1.csproj"
COPY . .
WORKDIR "/src/Exercise1"
RUN dotnet build "Exercise1.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Exercise1.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Exercise1.dll"]
