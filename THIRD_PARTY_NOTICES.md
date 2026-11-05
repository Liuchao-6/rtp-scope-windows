# Third-party notices

## G.729 / libjitsi

Source: https://github.com/jitsi/libjitsi at commit `afe642c2d9d00709ca71abbab893ab47b5b0b4ef`.

The 31 upstream Java files are distributed unchanged under Apache-2.0, retaining Atlassian and embedded ITU-T / AT&T / France Telecom / NTT / University of Sherbrooke notices. File SHA-256 values are in `third_party/g729-upstream.json`. The complete license is included in `src/main/resources/licenses/libjitsi-LICENSE.txt`, in the application JAR, and accessible through the About view. `G729Codec.java` is the project-owned RTP adapter.

## Eclipse Temurin / OpenJDK runtime

The portable application includes an unmodified Eclipse Temurin 8 Windows x64 JRE, distributed under GPL-2.0 with the Classpath Exception and the additional licenses/notices included in `runtime/LICENSE`, `runtime/ASSEMBLY_EXCEPTION`, `runtime/THIRD_PARTY_README` and runtime license directories. The original runtime files and license notices are retained.

Pinned release, official archive URL, SHA-256 and corresponding source location are recorded in `third_party/runtime.json`. Source is available from the Adoptium project at https://github.com/adoptium/jdk8u/releases/tag/jdk8u504-b01_adopt . Distributors should retain these notices and the runtime's own license files.

## FlatLaf

FlatLaf 3.6.2 by FormDev Software GmbH is distributed under Apache-2.0. The unmodified official JAR is included at `third_party/flatlaf-3.6.2.jar` in the source package and `app/lib/flatlaf-3.6.2.jar` in the portable application. Its Maven Central URL, source URL and SHA-256 are pinned in `third_party/flatlaf.json`.

The complete upstream license is retained inside the dependency JAR and in `src/main/resources/licenses/flatlaf-LICENSE.txt`, which is also embedded in the application JAR and accessible through the About view. Source: https://github.com/JFormDesigner/FlatLaf/tree/3.6.2 .

## Build and test tools

Eclipse ECJ is a build-only compiler and is not shipped in the portable application or source ZIP. FFmpeg was used as an independent decoder oracle for the synthetic G.729 reference fixture; FFmpeg is not included. Wireshark / tshark and Npcap are optional, separately installed tools and are not bundled.
