DS2 Seamless Co-op — Joiner Setup
==================================


ACCOUNT SAFETY — READ THIS FIRST
---------------------------------

Use a brand-new "throwaway" character for seamless co-op. Do NOT use your
main character. Do NOT take a character that has played seamless co-op
back into vanilla online play.

Why this matters
~~~~~~~~~~~~~~~~

Dark Souls II does not use VAC bans, but FromSoftware runs a "soft-ban"
system. A soft-banned character is quietly pooled into a matchmaking
ghetto with other soft-banned players — you keep playing but only ever
match with other cheaters. It is per-character, not per-account, and as
far as anyone knows it is not reversible.

Triggers we know of include:
  - Abnormal Soul Memory or item stacks.
  - Save files that were imported from another player ("mule saves").
  - (Suspected) using known fan patches the matchmaking server can
    fingerprint.

This mod redirects all matchmaking traffic to a private server, so a
seamless session itself never talks to FromSoftware. The risk is what
happens AFTER. If you take a character that played seamless co-op back
into vanilla online — with elevated Soul Memory, equipment received from
session members, or other modded-session artifacts — FromSoftware's
servers may flag the character, and the soft-ban they apply is silent
and permanent.

The mod does not currently segregate save files (separate save folder
for seamless sessions is on the roadmap). Until it does, the seamless
character lives in the same DS2SOFS0000.sl2 as the rest of your roster.
Treat that .sl2 with care.

Make a throwaway character (text walkthrough)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Do this BEFORE installing the mod, while the game is still vanilla.

  1. Launch Dark Souls II through Steam as normal.
  2. From the main menu choose New Game.
  3. Pick any starting class and gift. The character will never see
     vanilla online play, so optimisation does not matter.
  4. Name the character something obvious like "coop" or "seamless"
     so you don't pick it by mistake later.
  5. Finish character creation and let the game save once on the first
     bonfire. Quit to the main menu.
  6. Exit the game. Do not log in to a Sunbro covenant, do not summon,
     do not invade.
  7. (Strongly recommended) Back up DS2SOFS0000.sl2 from
     %APPDATA%\DarkSoulsII\<numeric-id>\ to somewhere outside the game
     folder. The whole point of a throwaway is that you can delete it
     and start over if anything goes wrong, but having the pre-install
     backup as well costs nothing.

Now you can install the mod and use the throwaway character for every
seamless session.

Hard rules
~~~~~~~~~~

  - The throwaway character must NEVER be loaded in vanilla online mode
    after a seamless session. Offline only, or only in another seamless
    session.
  - Do not transfer items or souls from the throwaway character to your
    main. Anything you received in a seamless session is potentially
    soft-ban kindling.
  - If you want to retire the throwaway, delete it. Do not promote it.

Screenshots for each step are a follow-up — for now this text walkthrough
is the authoritative install-time guidance.


INSTALL STEPS
-------------

1. Copy ALL files from this folder into:
   Steam/steamapps/common/Dark Souls II Scholar of the First Sin/Game/

2. Open ds2_seamless_coop.ini in Notepad

3. Change server_ip=CHANGE_ME to your friend's Hamachi IP
   Example: server_ip=25.47.123.456

4. Make sure you and your friend are on the same Hamachi network

5. Launch Dark Souls II through Steam

6. Press INSERT in-game to open the co-op menu

7. Click "Join Session", enter your friend's IP and the session password

8. Use the White Sign Soapstone to summon each other — make sure you
   loaded the throwaway character from the section above, NOT your main.

To remove the mod: run uninstall.cmd from this folder. It will close-check
the game, then remove dinput8.dll, ds2_seamless_coop.ini, and
ds2_server_public.key from your DS2 Game folder. Your DS2 saves are not
touched.
