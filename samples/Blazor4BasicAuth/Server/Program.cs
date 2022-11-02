using Blazor4BasicAuth.Server;
using Blazor4BasicAuth.Server.Models;
using Microsoft.AspNetCore.Authentication.Basic;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

builder.Services.AddDbContext<ApplicationDbContext>(opt =>
{
    opt.UseInMemoryDatabase("BlazorDB");
});

builder.Services
    .AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme)
    .AddBasic<SampleBasicUserAuthenticator>(opt => opt.Realm = "Blazor App");

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseBlazorFrameworkFiles();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();
app.MapFallbackToFile("index.html");

using (var scope = app.Services.CreateScope())
{
    using var efContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    efContext.Users.AddRange(new User[]
    {
        new(){ Id = 1, Account = "alice", Password = "123456" } // DO NOT store plain passwords into DB in your production!
    });
    efContext.SaveChanges();
}

app.Run();