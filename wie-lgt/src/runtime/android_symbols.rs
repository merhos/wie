//! Candidate bindings for Android-linked LGT/WIPI modules.
//!
//! A matching symbol name does NOT establish that the ABI is identical.
//! The ELF loader remains non-executable until foreign ABI verification.

use super::svc_ids::WIPICSvcId;

pub(super) fn wipi_candidate(name: &str) -> Option<WIPICSvcId> {
    Some(match name {
        "MC_netSocketWrite" => WIPICSvcId::SocketWrite,
        "MC_netSocketRead" => WIPICSvcId::SocketRead,
        "MC_netSocketClose" => WIPICSvcId::SocketClose,
        "MC_mdaClipCreate" => WIPICSvcId::ClipCreate,
        "MC_mdaPlay" => WIPICSvcId::Play,
        "MC_fsFileAttribute" => WIPICSvcId::FsFileAttribute,
        "MC_grpCreateImage" => WIPICSvcId::CreateImage,
        "MC_fsWrite" => WIPICSvcId::FsWrite,
        "MC_knlGetCurProgramID" => WIPICSvcId::GetCurProgramId,
        "MC_mdaClipClearData" => WIPICSvcId::ClipClearData,
        "MC_netSetReadCB" => WIPICSvcId::SetReadCallback,
        "MC_grpGetContext" => WIPICSvcId::GetContext,
        "MC_knlSprintk" => WIPICSvcId::Sprintk,
        "MC_grpDestroyOffScreenFrameBuffer" => WIPICSvcId::DestroyOffscreenFramebuffer,
        "MC_grpSetContext" => WIPICSvcId::SetContext,
        "MC_utilHtonl" | "MC_utilNtohl" => WIPICSvcId::Htonl,
        "MC_knlGetFreeMemory" => WIPICSvcId::GetFreeMemory,
        "MC_grpFlushLcd" => WIPICSvcId::FlushLcd,
        "MC_knlDefTimer" => WIPICSvcId::DefTimer,
        "MC_grpDrawLine" => WIPICSvcId::DrawLine,
        "MC_mdaClipFree" => WIPICSvcId::ClipFree,
        "MC_knlGetResource" => WIPICSvcId::GetResource,
        "MC_grpFillArc" => WIPICSvcId::FillArc,
        "MC_grpGetImageProperty" => WIPICSvcId::GetImageProperty,
        "MC_fsClose" => WIPICSvcId::FsClose,
        "MC_grpDrawArc" => WIPICSvcId::DrawArc,
        "MC_knlFree" => WIPICSvcId::Free,
        "MC_mdaVibrator" => WIPICSvcId::Vibrator,
        "MC_fsOpen" => WIPICSvcId::FsOpen,
        "MC_grpGetScreenFrameBuffer" => WIPICSvcId::GetScreenFramebuffer,
        "MC_knlAlloc" => WIPICSvcId::Alloc,
        "MC_fsSeek" => WIPICSvcId::FsSeek,
        "MC_grpDrawImage" => WIPICSvcId::DrawImage,
        "MC_knlGetTotalMemory" => WIPICSvcId::GetTotalMemory,
        "MC_utilHtons" => WIPICSvcId::Htons,
        "MC_fsRead" => WIPICSvcId::FsRead,
        "MC_grpCreateOffScreenFrameBuffer" => WIPICSvcId::CreateOffscreenFramebuffer,
        "MC_grpGetRGBFromPixel" => WIPICSvcId::GetRgbFromPixel,
        "MC_fsRemove" => WIPICSvcId::FsRemove,
        "MC_knlGetSystemProperty" => WIPICSvcId::GetSystemProperty,
        "MC_knlGetResourceID" => WIPICSvcId::GetResourceId,
        "MC_netClose" => WIPICSvcId::Close,
        "wipic_get_frame_height" => WIPICSvcId::GetFramebufferHeight,
        "wipic_get_frame_pointer" => WIPICSvcId::GetFramebufferPointer,
        "MC_grpGetPixelFromRGB" => WIPICSvcId::GetPixelFromRgb,
        "MC_knlExit" => WIPICSvcId::Exit,
        "MC_grpGetDisplayInfo" => WIPICSvcId::GetDisplayInfo,
        "MC_miscBackLight" => WIPICSvcId::BackLight,
        "MC_mdaClipSetVolume" => WIPICSvcId::ClipSetVolume,
        "MC_mdaSetMuteState" => WIPICSvcId::SetMuteState,
        "MC_grpDestroyImage" => WIPICSvcId::DestroyImage,
        "MC_knlSetTimer" => WIPICSvcId::SetTimer,
        "wipic_get_frame_width" => WIPICSvcId::GetFramebufferWidth,
        "MC_grpFillRect" => WIPICSvcId::FillRect,
        "MC_knlUnsetTimer" => WIPICSvcId::UnsetTimer,
        "MC_mdaClipAllocPlayer" => WIPICSvcId::ClipAllocPlayer,
        "MC_grpDrawRect" => WIPICSvcId::DrawRect,
        "MC_netConnect" => WIPICSvcId::Connect,
        "MC_knlCurrentTime" => WIPICSvcId::CurrentTime,
        "MC_netSocketConnect" => WIPICSvcId::SocketConnect,
        "MC_knlPrintk" => WIPICSvcId::Printk,
        "MC_netSetWriteCB" => WIPICSvcId::SetWriteCallback,
        "MC_mdaStop" => WIPICSvcId::Stop,
        "MC_grpInitContext" => WIPICSvcId::InitContext,
        "MC_knlCalloc" => WIPICSvcId::Calloc,
        "MC_mdaClipPutData" => WIPICSvcId::ClipPutData,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_wipi_imports_resolve_to_real_handler_ids() {
        assert_eq!(wipi_candidate("MC_knlSprintk").map(u32::from), Some(u32::from(WIPICSvcId::Sprintk)));
        assert_eq!(wipi_candidate("MC_grpFlushLcd").map(u32::from), Some(u32::from(WIPICSvcId::FlushLcd)));
        assert_eq!(wipi_candidate("MC_utilNtohl").map(u32::from), Some(u32::from(WIPICSvcId::Htonl)));
    }
    #[test]
    fn no_unverified_phone_or_android_imports_are_synthesized() {
        for name in ["MC_phnCallPlace", "MC_netBillSocket", "MC_netGetHostAddr", "__aeabi_ddiv", "dlet_set_property", "wipic_event_handler"] {
            assert!(wipi_candidate(name).is_none(), "{name}");
        }
    }
}
