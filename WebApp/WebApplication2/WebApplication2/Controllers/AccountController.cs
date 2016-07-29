using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using WebApplication2.Models;
using UnityEngine;
using System.Runtime.InteropServices;

namespace WebApplication2.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager )
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set 
            { 
                _signInManager = value; 
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            string req = Request.QueryString["method"];
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, change to shouldLockout: true
            var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid login attempt.");
                    return View(model);
            }
        }

        //
        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent:  model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await SignInManager.SignInAsync(user, isPersistent:false, rememberBrowser:false);
                    
                    // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                    // Send an email with this link
                    // string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                    // var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    // await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

                    return RedirectToAction("Index", "Home");
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var result = await UserManager.ConfirmEmailAsync(userId, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                // string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                // var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);		
                // await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                // return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/SendCode
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Sign in the user with this external login provider if the user already has a login
            var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
                case SignInStatus.Failure:
                default:
                    // If the user does not have an account, then prompt the user to create an account
                    ViewBag.ReturnUrl = returnUrl;
                    ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                    return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }

    // comment or uncomment the following #define directives
// depending on whether you use KinectExtras together with KinectManager

//#define USE_KINECT_INTERACTION_OR_FACETRACKING
//#define USE_SPEECH_RECOGNITION

// Wrapper class that holds the various structs and dll imports
// needed to set up a model with the Kinect.
public class KinectWrapper
    {
        public static class Constants
        {
            public const int NuiSkeletonCount = 6;
            public const int NuiSkeletonMaxTracked = 2;
            public const int NuiSkeletonInvalidTrackingID = 0;

            public const float NuiDepthHorizontalFOV = 58.5f;
            public const float NuiDepthVerticalFOV = 45.6f;

            public const int ColorImageWidth = 640;
            public const int ColorImageHeight = 480;
            public const NuiImageResolution ColorImageResolution = NuiImageResolution.resolution640x480;

            public const int DepthImageWidth = 640;
            public const int DepthImageHeight = 480;
            public const NuiImageResolution DepthImageResolution = NuiImageResolution.resolution640x480;

            public const bool IsNearMode = false;

            public const float MinTimeBetweenSameGestures = 0.0f;
            public const float PoseCompleteDuration = 1.0f;
            public const float ClickStayDuration = 2.5f;
        }

        /// <summary>
        ///Structs and constants for interfacing C# with the Kinect.dll 
        /// </summary>

        [Flags]
        public enum NuiInitializeFlags : uint
        {
            UsesAudio = 0x10000000,
            UsesDepthAndPlayerIndex = 0x00000001,
            UsesColor = 0x00000002,
            UsesSkeleton = 0x00000008,
            UsesDepth = 0x00000020,
            UsesHighQualityColor = 0x00000040
        }

        public enum NuiErrorCodes : uint
        {
            FrameNoData = 0x83010001,
            StreamNotEnabled = 0x83010002,
            ImageStreamInUse = 0x83010003,
            FrameLimitExceeded = 0x83010004,
            FeatureNotInitialized = 0x83010005,
            DeviceNotGenuine = 0x83010006,
            InsufficientBandwidth = 0x83010007,
            DeviceNotSupported = 0x83010008,
            DeviceInUse = 0x83010009,

            DatabaseNotFound = 0x8301000D,
            DatabaseVersionMismatch = 0x8301000E,
            HardwareFeatureUnavailable = 0x8301000F,

            DeviceNotConnected = 0x83010014,
            DeviceNotReady = 0x83010015,
            SkeletalEngineBusy = 0x830100AA,
            DeviceNotPowered = 0x8301027F,
        }

        public enum NuiSkeletonPositionIndex : int
        {
            HipCenter = 0,
            Spine = 1,
            ShoulderCenter = 2,
            Head = 3,
            ShoulderLeft = 4,
            ElbowLeft = 5,
            WristLeft = 6,
            HandLeft = 7,
            ShoulderRight = 8,
            ElbowRight = 9,
            WristRight = 10,
            HandRight = 11,
            HipLeft = 12,
            KneeLeft = 13,
            AnkleLeft = 14,
            FootLeft = 15,
            HipRight = 16,
            KneeRight = 17,
            AnkleRight = 18,
            FootRight = 19,
            Count = 20
        }

        public enum NuiSkeletonPositionTrackingState
        {
            NotTracked = 0,
            Inferred,
            Tracked
        }

        public enum NuiSkeletonTrackingState
        {
            NotTracked = 0,
            PositionOnly,
            SkeletonTracked
        }

        public enum NuiImageType
        {
            DepthAndPlayerIndex = 0,    // USHORT
            Color,                      // RGB32 data
            ColorYUV,                   // YUY2 stream from camera h/w, but converted to RGB32 before user getting it.
            ColorRawYUV,                // YUY2 stream from camera h/w.
            Depth                       // USHORT
        }

        public enum NuiImageResolution
        {
            resolutionInvalid = -1,
            resolution80x60 = 0,
            resolution320x240 = 1,
            resolution640x480 = 2,
            resolution1280x960 = 3     // for hires color only
        }

        public enum NuiImageStreamFlags
        {
            None = 0x00000000,
            SupressNoFrameData = 0x0001000,
            EnableNearMode = 0x00020000,
            TooFarIsNonZero = 0x0004000
        }

        [Flags]
        public enum FrameEdges
        {
            None = 0,
            Right = 1,
            Left = 2,
            Top = 4,
            Bottom = 8
        }

        public struct NuiSkeletonData
        {
            public NuiSkeletonTrackingState eTrackingState;
            public uint dwTrackingID;
            public uint dwEnrollmentIndex_NotUsed;
            public uint dwUserIndex;
            public Vector4 Position;
            [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 20, ArraySubType = UnmanagedType.Struct)]
            public Vector4[] SkeletonPositions;
            [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 20, ArraySubType = UnmanagedType.Struct)]
            public NuiSkeletonPositionTrackingState[] eSkeletonPositionTrackingState;
            public uint dwQualityFlags;
        }

        public struct NuiSkeletonFrame
        {
            public Int64 liTimeStamp;
            public uint dwFrameNumber;
            public uint dwFlags;
            public Vector4 vFloorClipPlane;
            public Vector4 vNormalToGravity;
            [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.Struct)]
            public NuiSkeletonData[] SkeletonData;
        }

        public struct NuiTransformSmoothParameters
        {
            public float fSmoothing;
            public float fCorrection;
            public float fPrediction;
            public float fJitterRadius;
            public float fMaxDeviationRadius;
        }

        public struct NuiSkeletonBoneRotation
        {
            public Matrix4x4 rotationMatrix;
            public Quaternion rotationQuaternion;
        }

        public struct NuiSkeletonBoneOrientation
        {
            public NuiSkeletonPositionIndex endJoint;
            public NuiSkeletonPositionIndex startJoint;
            public NuiSkeletonBoneRotation hierarchicalRotation;
            public NuiSkeletonBoneRotation absoluteRotation;
        }

        public struct NuiImageViewArea
        {
            public int eDigitalZoom;
            public int lCenterX;
            public int lCenterY;
        }

        public class NuiImageBuffer
        {
            public int m_Width;
            public int m_Height;
            public int m_BytesPerPixel;
            public IntPtr m_pBuffer;
        }

        public struct NuiImageFrame
        {
            public Int64 liTimeStamp;
            public uint dwFrameNumber;
            public NuiImageType eImageType;
            public NuiImageResolution eResolution;
            //[MarshalAsAttribute(UnmanagedType.Interface)]
            public IntPtr pFrameTexture;
            public uint dwFrameFlags_NotUsed;
            public NuiImageViewArea ViewArea_NotUsed;
        }

        public struct NuiLockedRect
        {
            public int pitch;
            public int size;
            //[MarshalAsAttribute(UnmanagedType.U8)] 
            public IntPtr pBits;

        }

        public struct ColorCust
        {
            public byte b;
            public byte g;
            public byte r;
            public byte a;
        }

        public struct ColorBuffer
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 640 * 480, ArraySubType = UnmanagedType.Struct)]
            public ColorCust[] pixels;
        }

        public struct DepthBuffer
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 640 * 480, ArraySubType = UnmanagedType.U2)]
            public ushort[] pixels;
        }

        public struct NuiSurfaceDesc
        {
            uint width;
            uint height;
        }

        [Guid("13ea17f5-ff2e-4670-9ee5-1297a6e880d1")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        [ComImport()]
        public interface INuiFrameTexture
        {
            //[MethodImpl (MethodImplOptions.InternalCall, MethodCodeType=MethodCodeType.Runtime)]
            [PreserveSig]
            int BufferLen();
            //[MethodImpl (MethodImplOptions.InternalCall, MethodCodeType=MethodCodeType.Runtime)]
            [PreserveSig]
            int Pitch();
            //[MethodImpl (MethodImplOptions.InternalCall, MethodCodeType=MethodCodeType.Runtime)]
            [PreserveSig]
            int LockRect(uint Level, ref NuiLockedRect pLockedRect, IntPtr pRect, uint Flags);
            //[MethodImpl (MethodImplOptions.InternalCall, MethodCodeType=MethodCodeType.Runtime)]
            [PreserveSig]
            //[MethodImpl (MethodImplOptions.InternalCall, MethodCodeType=MethodCodeType.Runtime)]
            int GetLevelDesc(uint Level, ref NuiSurfaceDesc pDesc);
            [PreserveSig]
            int UnlockRect(uint Level);
        }

        /* 
         * kinect NUI (general) functions
         */
#if USE_KINECT_INTERACTION_OR_FACETRACKING || USE_SPEECH_RECOGNITION
	[DllImportAttribute(@"KinectUnityWrapper.dll", EntryPoint = "InitKinectSensor")]
	public static extern int InitKinectSensor(NuiInitializeFlags dwFlags, bool bEnableEvents, int iColorResolution, int iDepthResolution, bool bNearMode);

	[DllImportAttribute(@"KinectUnityWrapper.dll", EntryPoint = "EnableKinectManager")]
	public static extern void EnableKinectManager(bool bEnable);
	
	[DllImportAttribute(@"KinectUnityWrapper.dll", EntryPoint = "UpdateKinectSensor")]
	public static extern int UpdateKinectSensor();
#else
        [DllImportAttribute(@"Kinect10.dll", EntryPoint = "NuiInitialize")]
        public static extern int NuiInitialize(NuiInitializeFlags dwFlags);
#endif

#if USE_KINECT_INTERACTION_OR_FACETRACKING && USE_SPEECH_RECOGNITION
    public static int NuiInitialize(NuiInitializeFlags dwFlags)
	{
		EnableKinectManager(true);
		return InitKinectSensor(dwFlags|NuiInitializeFlags.UsesAudio, true, (int)Constants.ColorImageResolution, (int)Constants.DepthImageResolution, Constants.IsNearMode);
	}
#elif USE_KINECT_INTERACTION_OR_FACETRACKING
    public static int NuiInitialize(NuiInitializeFlags dwFlags)
	{
		EnableKinectManager(true);
		return InitKinectSensor(dwFlags, true, (int)Constants.ColorImageResolution, (int)Constants.DepthImageResolution, Constants.IsNearMode);
	}
#elif USE_SPEECH_RECOGNITION
    public static int NuiInitialize(NuiInitializeFlags dwFlags)
	{
		EnableKinectManager(true);
		return InitKinectSensor(dwFlags|NuiInitializeFlags.UsesAudio, true, (int)Constants.ColorImageResolution, (int)Constants.DepthImageResolution, Constants.IsNearMode);
	}
#endif

#if USE_KINECT_INTERACTION_OR_FACETRACKING || USE_SPEECH_RECOGNITION
	[DllImportAttribute(@"KinectUnityWrapper.dll", EntryPoint = "ShutdownKinectSensor")]
	public static extern void ShutdownKinectSensor();
	
	[DllImportAttribute(@"KinectUnityWrapper.dll", EntryPoint = "SetKinectElevationAngle")]
	public static extern int SetKinectElevationAngle(int sensorAngle);
	
	[DllImportAttribute(@"KinectUnityWrapper.dll", EntryPoint = "GetKinectElevationAngle")]
    public static extern int GetKinectElevationAngle();
	
    public static void NuiShutdown()
	{
		ShutdownKinectSensor();
	}
	
	public static int NuiCameraElevationSetAngle(int angle)
	{
		return SetKinectElevationAngle(angle);
	}
	
    public static int NuiCameraElevationGetAngle(out int plAngleDegrees)
	{
		plAngleDegrees = GetKinectElevationAngle();
		return 0;
	}
#else
        [DllImportAttribute(@"Kinect10.dll", EntryPoint = "NuiShutdown")]
        public static extern void NuiShutdown();

        [DllImportAttribute(@"Kinect10.dll", EntryPoint = "NuiCameraElevationSetAngle")]
        public static extern int NuiCameraElevationSetAngle(int angle);

        [DllImportAttribute(@"Kinect10.dll", EntryPoint = "NuiCameraElevationGetAngle")]
        public static extern int NuiCameraElevationGetAngle(out int plAngleDegrees);
#endif

        [DllImport(@"Kinect10.dll", EntryPoint = "NuiImageGetColorPixelCoordinatesFromDepthPixelAtResolution")]
        public static extern int NuiImageGetColorPixelCoordinatesFromDepthPixelAtResolution(NuiImageResolution eColorResolution, NuiImageResolution eDepthResolution, ref NuiImageViewArea pcViewArea, int lDepthX, int lDepthY, ushort sDepthValue, out int plColorX, out int plColorY);

        [DllImport(@"Kinect10.dll", EntryPoint = "NuiGetSensorCount")]
        public static extern int NuiGetSensorCount(out int pCount);

        /*
         * kinect skeleton functions
         */
#if USE_KINECT_INTERACTION_OR_FACETRACKING || USE_SPEECH_RECOGNITION
    public static int NuiSkeletonTrackingEnable(IntPtr hNextFrameEvent, uint dwFlags)
	{
		// already enabled on init
		return 0;
	}
#else
        [DllImportAttribute(@"Kinect10.dll", EntryPoint = "NuiSkeletonTrackingEnable")]
        public static extern int NuiSkeletonTrackingEnable(IntPtr hNextFrameEvent, uint dwFlags);
#endif

#if USE_KINECT_INTERACTION_OR_FACETRACKING || USE_SPEECH_RECOGNITION
	[DllImport(@"KinectUnityWrapper.dll", EntryPoint = "GetSkeletonFrameLength")]
	public static extern int GetSkeletonFrameLength();

	[DllImport(@"KinectUnityWrapper.dll", EntryPoint = "GetSkeletonFrameData")]
	public static extern bool GetSkeletonFrameData(ref NuiSkeletonFrame pSkeletonData, ref uint iDataBufLen, bool bNewFrame);

	[DllImport(@"KinectUnityWrapper.dll", EntryPoint = "GetNextSkeletonFrame")]
	public static extern int GetNextSkeletonFrame(uint dwWaitMs);
#else
        [DllImportAttribute(@"Kinect10.dll", EntryPoint = "NuiSkeletonGetNextFrame")]
        public static extern int NuiSkeletonGetNextFrame(uint dwMillisecondsToWait, ref NuiSkeletonFrame pSkeletonFrame);
#endif

#if USE_KINECT_INTERACTION_OR_FACETRACKING
    public static int NuiSkeletonGetNextFrame(uint dwMillisecondsToWait, ref NuiSkeletonFrame pSkeletonFrame)
	{
		uint iFrameLength = (uint)GetSkeletonFrameLength();
		bool bSuccess = GetSkeletonFrameData(ref pSkeletonFrame, ref iFrameLength, true);
		return bSuccess ? 0 : -1;
	}
#elif USE_SPEECH_RECOGNITION
    public static int NuiSkeletonGetNextFrame(uint dwMillisecondsToWait, ref NuiSkeletonFrame pSkeletonFrame)
	{
		int hr = GetNextSkeletonFrame(dwMillisecondsToWait);
		if(hr == 0)
		{
			uint iFrameLength = (uint)GetSkeletonFrameLength();
			bool bSuccess = GetSkeletonFrameData(ref pSkeletonFrame, ref iFrameLength, true);
			
			return bSuccess ? 0 : -1;
		}
		
		return hr;
	}
#endif

        [DllImportAttribute(@"Kinect10.dll", EntryPoint = "NuiTransformSmooth")]
        public static extern int NuiTransformSmooth(ref NuiSkeletonFrame pSkeletonFrame, ref NuiTransformSmoothParameters pSmoothingParams);

        [DllImport(@"Kinect10.dll", EntryPoint = "NuiSkeletonCalculateBoneOrientations")]
        public static extern int NuiSkeletonCalculateBoneOrientations(ref NuiSkeletonData pSkeletonData, NuiSkeletonBoneOrientation[] pBoneOrientations);

        /*
         * kinect video functions
         */
#if USE_KINECT_INTERACTION_OR_FACETRACKING || USE_SPEECH_RECOGNITION
	[DllImport(@"KinectUnityWrapper.dll", EntryPoint = "GetColorStreamHandle")]
	public static extern IntPtr GetColorStreamHandle();

	[DllImport(@"KinectUnityWrapper.dll", EntryPoint = "GetDepthStreamHandle")]
	public static extern IntPtr GetDepthStreamHandle();

	[DllImport(@"KinectUnityWrapper.dll", EntryPoint = "GetColorFrameData")]
	public static extern bool GetColorFrameData(IntPtr btVideoBuf, ref uint iVideoBufLen, bool bGetNewFrame);
	
	[DllImport(@"KinectUnityWrapper.dll", EntryPoint = "GetDepthFrameData")]
	public static extern bool GetDepthFrameData(IntPtr shDepthBuf, ref uint iDepthBufLen, bool bGetNewFrame);
	
	public static int NuiImageStreamOpen(NuiImageType eImageType, NuiImageResolution eResolution, uint dwImageFrameFlags_NotUsed, uint dwFrameLimit, IntPtr hNextFrameEvent, ref IntPtr phStreamHandle)
	{
		if(eImageType == NuiImageType.DepthAndPlayerIndex)
			phStreamHandle =  GetDepthStreamHandle();
		else if(eImageType == NuiImageType.Color)
			phStreamHandle =  GetColorStreamHandle();
		else
			throw new Exception("Unsupported image type: " + eImageType);
		
		return 0;
	}
#else
        [DllImportAttribute(@"Kinect10.dll", EntryPoint = "NuiImageStreamOpen")]
        public static extern int NuiImageStreamOpen(NuiImageType eImageType, NuiImageResolution eResolution, uint dwImageFrameFlags_NotUsed, uint dwFrameLimit, IntPtr hNextFrameEvent, ref IntPtr phStreamHandle);
#endif

        [DllImportAttribute(@"Kinect10.dll", EntryPoint = "NuiImageStreamGetNextFrame")]
        public static extern int NuiImageStreamGetNextFrame(IntPtr phStreamHandle, uint dwMillisecondsToWait, ref IntPtr ppcImageFrame);

        [DllImportAttribute(@"Kinect10.dll", EntryPoint = "NuiImageStreamReleaseFrame")]
        public static extern int NuiImageStreamReleaseFrame(IntPtr phStreamHandle, IntPtr ppcImageFrame);

        [DllImportAttribute(@"Kinect10.dll", EntryPoint = "NuiImageStreamSetImageFrameFlags")]
        public static extern int NuiImageStreamSetImageFrameFlags(IntPtr phStreamHandle, NuiImageStreamFlags dvImageFrameFlags);

        [DllImportAttribute(@"Kinect10.dll", EntryPoint = "NuiImageResolutionToSize")]
        public static extern int NuiImageResolutionToSize(NuiImageResolution eResolution, out uint frameWidth, out uint frameHeight);


        public static string GetNuiErrorString(int hr)
        {
            string message = string.Empty;
            uint uhr = (uint)hr;

            switch (uhr)
            {
                case (uint)NuiErrorCodes.FrameNoData:
                    message = "Frame contains no data.";
                    break;
                case (uint)NuiErrorCodes.StreamNotEnabled:
                    message = "Stream is not enabled.";
                    break;
                case (uint)NuiErrorCodes.ImageStreamInUse:
                    message = "Image stream is already in use.";
                    break;
                case (uint)NuiErrorCodes.FrameLimitExceeded:
                    message = "Frame limit is exceeded.";
                    break;
                case (uint)NuiErrorCodes.FeatureNotInitialized:
                    message = "Feature is not initialized.";
                    break;
                case (uint)NuiErrorCodes.DeviceNotGenuine:
                    message = "Device is not genuine.";
                    break;
                case (uint)NuiErrorCodes.InsufficientBandwidth:
                    message = "Bandwidth is not sufficient.";
                    break;
                case (uint)NuiErrorCodes.DeviceNotSupported:
                    message = "Device is not supported (e.g. Kinect for XBox 360).";
                    break;
                case (uint)NuiErrorCodes.DeviceInUse:
                    message = "Device is already in use.";
                    break;
                case (uint)NuiErrorCodes.DatabaseNotFound:
                    message = "Database not found.";
                    break;
                case (uint)NuiErrorCodes.DatabaseVersionMismatch:
                    message = "Database version mismatch.";
                    break;
                case (uint)NuiErrorCodes.HardwareFeatureUnavailable:
                    message = "Hardware feature is not available.";
                    break;
                case (uint)NuiErrorCodes.DeviceNotConnected:
                    message = "Device is not connected.";
                    break;
                case (uint)NuiErrorCodes.DeviceNotReady:
                    message = "Device is not ready.";
                    break;
                case (uint)NuiErrorCodes.SkeletalEngineBusy:
                    message = "Skeletal engine is busy.";
                    break;
                case (uint)NuiErrorCodes.DeviceNotPowered:
                    message = "Device is not powered.";
                    break;

                default:
                    message = "hr=0x" + uhr.ToString("X");
                    break;
            }

            return message;
        }

        public static int GetDepthWidth()
        {
            return Constants.DepthImageWidth;
        }

        public static int GetDepthHeight()
        {
            return Constants.DepthImageHeight;
        }

        public static int GetColorWidth()
        {
            return Constants.ColorImageWidth;
        }

        public static int GetColorHeight()
        {
            return Constants.ColorImageHeight;
        }

        public static Vector3 MapSkeletonPointToDepthPoint(Vector3 skeletonPoint)
        {
            float fDepthX;
            float fDepthY;
            float fDepthZ;

            NuiTransformSkeletonToDepthImage(skeletonPoint, out fDepthX, out fDepthY, out fDepthZ);

            Vector3 point = new Vector3();
            point.x = (int)((fDepthX * Constants.DepthImageWidth) + 0.5f);
            point.y = (int)((fDepthY * Constants.DepthImageHeight) + 0.5f);
            point.z = (int)(fDepthZ + 0.5f);

            return point;
        }

        //    public static Vector3 MapSkeletonPointToColorPoint(Vector3 skeletonPoint)
        //    {
        //        float fDepthX;
        //        float fDepthY;
        //        float fDepthZ;
        //
        //		NuiTransformSkeletonToDepthImage(skeletonPoint, out fDepthX, out fDepthY, out fDepthZ);
        //        
        //		Vector3 point = new Vector3();
        //        point.x = (int) ((fDepthX * Constants.ImageWidth) + 0.5f);
        //        point.y = (int) ((fDepthY * Constants.ImageHeight) + 0.5f);
        //        point.z = (int) (fDepthZ + 0.5f);
        //
        //		return point;
        //    }

        private static void NuiTransformSkeletonToDepthImage(Vector3 vPoint, out float pfDepthX, out float pfDepthY, out float pfDepthZ)
        {
            if (vPoint.z > float.Epsilon)
            {
                pfDepthX = 0.5f + ((vPoint.x * 285.63f) / (vPoint.z * 320f));
                pfDepthY = 0.5f - ((vPoint.y * 285.63f) / (vPoint.z * 240f));
                pfDepthZ = vPoint.z * 1000f;
            }
            else
            {
                pfDepthX = 0f;
                pfDepthY = 0f;
                pfDepthZ = 0f;
            }
        }

        public static int GetSkeletonJointParent(int jointIndex)
        {
            switch (jointIndex)
            {
                case (int)NuiSkeletonPositionIndex.HipCenter:
                    return (int)NuiSkeletonPositionIndex.HipCenter;
                case (int)NuiSkeletonPositionIndex.Spine:
                    return (int)NuiSkeletonPositionIndex.HipCenter;
                case (int)NuiSkeletonPositionIndex.ShoulderCenter:
                    return (int)NuiSkeletonPositionIndex.Spine;
                case (int)NuiSkeletonPositionIndex.Head:
                    return (int)NuiSkeletonPositionIndex.ShoulderCenter;
                case (int)NuiSkeletonPositionIndex.ShoulderLeft:
                    return (int)NuiSkeletonPositionIndex.ShoulderCenter;
                case (int)NuiSkeletonPositionIndex.ElbowLeft:
                    return (int)NuiSkeletonPositionIndex.ShoulderLeft;
                case (int)NuiSkeletonPositionIndex.WristLeft:
                    return (int)NuiSkeletonPositionIndex.ElbowLeft;
                case (int)NuiSkeletonPositionIndex.HandLeft:
                    return (int)NuiSkeletonPositionIndex.WristLeft;
                case (int)NuiSkeletonPositionIndex.ShoulderRight:
                    return (int)NuiSkeletonPositionIndex.ShoulderCenter;
                case (int)NuiSkeletonPositionIndex.ElbowRight:
                    return (int)NuiSkeletonPositionIndex.ShoulderRight;
                case (int)NuiSkeletonPositionIndex.WristRight:
                    return (int)NuiSkeletonPositionIndex.ElbowRight;
                case (int)NuiSkeletonPositionIndex.HandRight:
                    return (int)NuiSkeletonPositionIndex.WristRight;
                case (int)NuiSkeletonPositionIndex.HipLeft:
                    return (int)NuiSkeletonPositionIndex.HipCenter;
                case (int)NuiSkeletonPositionIndex.KneeLeft:
                    return (int)NuiSkeletonPositionIndex.HipLeft;
                case (int)NuiSkeletonPositionIndex.AnkleLeft:
                    return (int)NuiSkeletonPositionIndex.KneeLeft;
                case (int)NuiSkeletonPositionIndex.FootLeft:
                    return (int)NuiSkeletonPositionIndex.AnkleLeft;
                case (int)NuiSkeletonPositionIndex.HipRight:
                    return (int)NuiSkeletonPositionIndex.HipCenter;
                case (int)NuiSkeletonPositionIndex.KneeRight:
                    return (int)NuiSkeletonPositionIndex.HipRight;
                case (int)NuiSkeletonPositionIndex.AnkleRight:
                    return (int)NuiSkeletonPositionIndex.KneeRight;
                case (int)NuiSkeletonPositionIndex.FootRight:
                    return (int)NuiSkeletonPositionIndex.AnkleRight;
            }

            return (int)NuiSkeletonPositionIndex.HipCenter;
        }

        public static int GetSkeletonMirroredJoint(int jointIndex)
        {
            switch (jointIndex)
            {
                case (int)NuiSkeletonPositionIndex.ShoulderLeft:
                    return (int)NuiSkeletonPositionIndex.ShoulderRight;
                case (int)NuiSkeletonPositionIndex.ElbowLeft:
                    return (int)NuiSkeletonPositionIndex.ElbowRight;
                case (int)NuiSkeletonPositionIndex.WristLeft:
                    return (int)NuiSkeletonPositionIndex.WristRight;
                case (int)NuiSkeletonPositionIndex.HandLeft:
                    return (int)NuiSkeletonPositionIndex.HandRight;
                case (int)NuiSkeletonPositionIndex.ShoulderRight:
                    return (int)NuiSkeletonPositionIndex.ShoulderLeft;
                case (int)NuiSkeletonPositionIndex.ElbowRight:
                    return (int)NuiSkeletonPositionIndex.ElbowLeft;
                case (int)NuiSkeletonPositionIndex.WristRight:
                    return (int)NuiSkeletonPositionIndex.WristLeft;
                case (int)NuiSkeletonPositionIndex.HandRight:
                    return (int)NuiSkeletonPositionIndex.HandLeft;
                case (int)NuiSkeletonPositionIndex.HipLeft:
                    return (int)NuiSkeletonPositionIndex.HipRight;
                case (int)NuiSkeletonPositionIndex.KneeLeft:
                    return (int)NuiSkeletonPositionIndex.KneeRight;
                case (int)NuiSkeletonPositionIndex.AnkleLeft:
                    return (int)NuiSkeletonPositionIndex.AnkleRight;
                case (int)NuiSkeletonPositionIndex.FootLeft:
                    return (int)NuiSkeletonPositionIndex.FootRight;
                case (int)NuiSkeletonPositionIndex.HipRight:
                    return (int)NuiSkeletonPositionIndex.HipLeft;
                case (int)NuiSkeletonPositionIndex.KneeRight:
                    return (int)NuiSkeletonPositionIndex.KneeLeft;
                case (int)NuiSkeletonPositionIndex.AnkleRight:
                    return (int)NuiSkeletonPositionIndex.AnkleLeft;
                case (int)NuiSkeletonPositionIndex.FootRight:
                    return (int)NuiSkeletonPositionIndex.FootLeft;
            }

            return jointIndex;
        }

        public static bool PollSkeleton(ref NuiTransformSmoothParameters smoothParameters, ref NuiSkeletonFrame skeletonFrame)
        {
            bool newSkeleton = false;

            int hr = KinectWrapper.NuiSkeletonGetNextFrame(0, ref skeletonFrame);
            if (hr == 0)
            {
                newSkeleton = true;
            }

            if (newSkeleton)
            {
                hr = KinectWrapper.NuiTransformSmooth(ref skeletonFrame, ref smoothParameters);
                if (hr != 0)
                {
                    Debug.Log("Skeleton Data Smoothing failed");
                }
            }

            return newSkeleton;
        }

        public static bool PollColor(IntPtr colorStreamHandle, ref byte[] videoBuffer, ref Color32[] colorImage)
        {
#if USE_KINECT_INTERACTION_OR_FACETRACKING
		uint videoBufLen = (uint)videoBuffer.Length;

		var pColorData = GCHandle.Alloc(videoBuffer, GCHandleType.Pinned);
		bool newColor = GetColorFrameData(pColorData.AddrOfPinnedObject(), ref videoBufLen, true);
		pColorData.Free();

		if (newColor)
		{
			int totalPixels = colorImage.Length;
			
			for (int pix = 0; pix < totalPixels; pix++)
			{
				int ind = pix; // totalPixels - pix - 1;
				int src = pix << 2;
				
				colorImage[ind].r = videoBuffer[src + 2]; // pixels[pix].r;
				colorImage[ind].g = videoBuffer[src + 1]; // pixels[pix].g;
				colorImage[ind].b = videoBuffer[src]; // pixels[pix].b;
				colorImage[ind].a = 255;
			}
		}
#else
            IntPtr imageFramePtr = IntPtr.Zero;
            bool newColor = false;

            int hr = KinectWrapper.NuiImageStreamGetNextFrame(colorStreamHandle, 0, ref imageFramePtr);
            if (hr == 0)
            {
                newColor = true;

                NuiImageFrame imageFrame = (NuiImageFrame)Marshal.PtrToStructure(imageFramePtr, typeof(NuiImageFrame));
                INuiFrameTexture frameTexture = (INuiFrameTexture)Marshal.GetObjectForIUnknown(imageFrame.pFrameTexture);

                NuiLockedRect lockedRectPtr = new NuiLockedRect();
                IntPtr r = IntPtr.Zero;

                frameTexture.LockRect(0, ref lockedRectPtr, r, 0);
                //ExtractColorImage(lockedRectPtr, ref colorImage);

                ColorBuffer cb = (ColorBuffer)Marshal.PtrToStructure(lockedRectPtr.pBits, typeof(ColorBuffer));
                int totalPixels = Constants.ColorImageWidth * Constants.ColorImageHeight;

                for (int pix = 0; pix < totalPixels; pix++)
                {
                    int ind = pix; // totalPixels - pix - 1;

                    colorImage[ind].r = cb.pixels[pix].r;
                    colorImage[ind].g = cb.pixels[pix].g;
                    colorImage[ind].b = cb.pixels[pix].b;
                    colorImage[ind].a = 255;
                }

                frameTexture.UnlockRect(0);
                hr = KinectWrapper.NuiImageStreamReleaseFrame(colorStreamHandle, imageFramePtr);
            }
#endif

            return newColor;
        }

        public static bool PollDepth(IntPtr depthStreamHandle, bool isNearMode, ref ushort[] depthPlayerData)
        {
#if USE_KINECT_INTERACTION_OR_FACETRACKING
		uint depthBufLen = (uint)(depthPlayerData.Length << 1);

		var pDepthData = GCHandle.Alloc(depthPlayerData, GCHandleType.Pinned);
		bool newDepth = GetDepthFrameData(pDepthData.AddrOfPinnedObject(), ref depthBufLen, true);
		pDepthData.Free();
#else
            IntPtr imageFramePtr = IntPtr.Zero;
            bool newDepth = false;

            if (isNearMode)
            {
                KinectWrapper.NuiImageStreamSetImageFrameFlags(depthStreamHandle, NuiImageStreamFlags.EnableNearMode);
            }
            else
            {
                KinectWrapper.NuiImageStreamSetImageFrameFlags(depthStreamHandle, NuiImageStreamFlags.None);
            }

            int hr = KinectWrapper.NuiImageStreamGetNextFrame(depthStreamHandle, 0, ref imageFramePtr);
            if (hr == 0)
            {
                newDepth = true;

                NuiImageFrame imageFrame = (NuiImageFrame)Marshal.PtrToStructure(imageFramePtr, typeof(NuiImageFrame));
                INuiFrameTexture frameTexture = (INuiFrameTexture)Marshal.GetObjectForIUnknown(imageFrame.pFrameTexture);

                NuiLockedRect lockedRectPtr = new NuiLockedRect();
                IntPtr r = IntPtr.Zero;

                frameTexture.LockRect(0, ref lockedRectPtr, r, 0);
                //depthPlayerData = ExtractDepthImage(lockedRectPtr);

                DepthBuffer db = (DepthBuffer)Marshal.PtrToStructure(lockedRectPtr.pBits, typeof(DepthBuffer));
                depthPlayerData = db.pixels;

                frameTexture.UnlockRect(0);
                hr = KinectWrapper.NuiImageStreamReleaseFrame(depthStreamHandle, imageFramePtr);
            }
#endif

            return newDepth;
        }

        //	private static void ExtractColorImage(NuiLockedRect buf, ref Color32[] colorImage)
        //	{
        //		ColorBuffer cb = (ColorBuffer)Marshal.PtrToStructure(buf.pBits, typeof(ColorBuffer));
        //		int totalPixels = Constants.ImageWidth * Constants.ImageHeight;
        //		
        //		for (int pix = 0; pix < totalPixels; pix++)
        //		{
        //			int ind = totalPixels - pix - 1;
        //			
        //			colorImage[ind].r = cb.pixels[pix].r;
        //			colorImage[ind].g = cb.pixels[pix].g;
        //			colorImage[ind].b = cb.pixels[pix].b;
        //			colorImage[ind].a = 255;
        //		}
        //	}
        //	
        //	private static short[] ExtractDepthImage(NuiLockedRect lockedRect)
        //	{
        //		DepthBuffer db = (DepthBuffer)Marshal.PtrToStructure(lockedRect.pBits, typeof(DepthBuffer));
        //		return db.pixels;
        //	}

        private static Vector3 GetPositionBetweenIndices(ref Vector3[] jointsPos, NuiSkeletonPositionIndex p1, NuiSkeletonPositionIndex p2)
        {
            Vector3 pVec1 = jointsPos[(int)p1];
            Vector3 pVec2 = jointsPos[(int)p2];

            return pVec2 - pVec1;
        }

        //populate matrix using the columns
        private static void PopulateMatrix(ref Matrix4x4 jointOrientation, Vector3 xCol, Vector3 yCol, Vector3 zCol)
        {
            jointOrientation.SetColumn(0, xCol);
            jointOrientation.SetColumn(1, yCol);
            jointOrientation.SetColumn(2, zCol);
        }

        //constructs an orientation from a vector that specifies the x axis
        private static void MakeMatrixFromX(Vector3 v1, ref Matrix4x4 jointOrientation, bool flip)
        {
            //matrix columns
            Vector3 xCol;
            Vector3 yCol;
            Vector3 zCol;

            //set first column to the vector between the previous joint and the current one, this sets the two degrees of freedom
            xCol = v1.normalized;

            //set second column to an arbitrary vector perpendicular to the first column
            yCol.x = 0.0f;
            yCol.y = !flip ? xCol.z : -xCol.z;
            yCol.z = !flip ? -xCol.y : xCol.y;
            yCol.Normalize();

            //third column is fully determined by the first two, and it must be their cross product
            zCol = Vector3.Cross(xCol, yCol);

            //copy values into matrix
            PopulateMatrix(ref jointOrientation, xCol, yCol, zCol);
        }

        //constructs an orientation from a vector that specifies the y axis
        private static void MakeMatrixFromY(Vector3 v1, ref Matrix4x4 jointOrientation)
        {
            //matrix columns
            Vector3 xCol;
            Vector3 yCol;
            Vector3 zCol;

            //set first column to the vector between the previous joint and the current one, this sets the two degrees of freedom
            yCol = v1.normalized;

            //set second column to an arbitrary vector perpendicular to the first column
            xCol.x = yCol.y;
            xCol.y = -yCol.x;
            xCol.z = 0.0f;
            xCol.Normalize();

            //third column is fully determined by the first two, and it must be their cross product
            zCol = Vector3.Cross(xCol, yCol);

            //copy values into matrix
            PopulateMatrix(ref jointOrientation, xCol, yCol, zCol);
        }

        //constructs an orientation from a vector that specifies the x axis
        private static void MakeMatrixFromZ(Vector3 v1, ref Matrix4x4 jointOrientation)
        {
            //matrix columns
            Vector3 xCol;
            Vector3 yCol;
            Vector3 zCol;

            //set first column to the vector between the previous joint and the current one, this sets the two degrees of freedom
            zCol = v1.normalized;

            //set second column to an arbitrary vector perpendicular to the first column
            xCol.x = zCol.y;
            xCol.y = -zCol.x;
            xCol.z = 0.0f;
            xCol.Normalize();

            //third column is fully determined by the first two, and it must be their cross product
            yCol = Vector3.Cross(zCol, xCol);

            //copy values into matrix
            PopulateMatrix(ref jointOrientation, xCol, yCol, zCol);
        }

        //constructs an orientation from 2 vectors: the first specifies the x axis, and the next specifies the y axis
        //uses the first vector as x axis, then constructs the other axes using cross products
        private static void MakeMatrixFromXY(Vector3 xUnnormalized, Vector3 yUnnormalized, ref Matrix4x4 jointOrientation)
        {
            //matrix columns
            Vector3 xCol;
            Vector3 yCol;
            Vector3 zCol;

            //set up the three different columns to be rearranged and flipped
            xCol = xUnnormalized.normalized;
            zCol = Vector3.Cross(xCol, yUnnormalized.normalized).normalized;
            yCol = Vector3.Cross(zCol, xCol).normalized;
            //yCol = yUnnormalized.normalized;
            //zCol = Vector3.Cross(xCol, yCol).normalized;

            //copy values into matrix
            PopulateMatrix(ref jointOrientation, xCol, yCol, zCol);
        }

        //constructs an orientation from 2 vectors: the first specifies the x axis, and the next specifies the y axis
        //uses the second vector as y axis, then constructs the other axes using cross products
        private static void MakeMatrixFromYX(Vector3 xUnnormalized, Vector3 yUnnormalized, ref Matrix4x4 jointOrientation)
        {
            //matrix columns
            Vector3 xCol;
            Vector3 yCol;
            Vector3 zCol;

            //set up the three different columns to be rearranged and flipped
            yCol = yUnnormalized.normalized;
            zCol = Vector3.Cross(xUnnormalized.normalized, yCol).normalized;
            xCol = Vector3.Cross(yCol, zCol).normalized;
            //xCol = xUnnormalized.normalized;
            //zCol = Vector3.Cross(xCol, yCol).normalized;

            //copy values into matrix
            PopulateMatrix(ref jointOrientation, xCol, yCol, zCol);
        }

        //constructs an orientation from 2 vectors: the first specifies the x axis, and the next specifies the y axis
        //uses the second vector as y axis, then constructs the other axes using cross products
        private static void MakeMatrixFromYZ(Vector3 yUnnormalized, Vector3 zUnnormalized, ref Matrix4x4 jointOrientation)
        {
            //matrix columns
            Vector3 xCol;
            Vector3 yCol;
            Vector3 zCol;

            //set up the three different columns to be rearranged and flipped
            yCol = yUnnormalized.normalized;
            xCol = Vector3.Cross(yCol, zUnnormalized.normalized).normalized;
            zCol = Vector3.Cross(xCol, yCol).normalized;
            //zCol = zUnnormalized.normalized;
            //xCol = Vector3.Cross(yCol, zCol).normalized;

            //copy values into matrix
            PopulateMatrix(ref jointOrientation, xCol, yCol, zCol);
        }

        // calculate the joint orientations, based on joint positions and their tracked state
        public static void GetSkeletonJointOrientation(ref Vector3[] jointsPos, ref bool[] jointsTracked, ref Matrix4x4[] jointOrients)
        {
            Vector3 vx;
            Vector3 vy;
            Vector3 vz;

            // NUI_SKELETON_POSITION_HIP_CENTER
            if (jointsTracked[(int)NuiSkeletonPositionIndex.HipCenter] && jointsTracked[(int)NuiSkeletonPositionIndex.Spine] &&
                jointsTracked[(int)NuiSkeletonPositionIndex.HipLeft] && jointsTracked[(int)NuiSkeletonPositionIndex.HipRight])
            {
                vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.HipCenter, NuiSkeletonPositionIndex.Spine);
                vx = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.HipLeft, NuiSkeletonPositionIndex.HipRight);
                MakeMatrixFromYX(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.HipCenter]);

                // make a correction of about 40 degrees back to the front
                Matrix4x4 mat = jointOrients[(int)NuiSkeletonPositionIndex.HipCenter];
                Quaternion quat = Quaternion.LookRotation(mat.GetColumn(2), mat.GetColumn(1));
                quat *= Quaternion.Euler(-40, 0, 0);
                jointOrients[(int)NuiSkeletonPositionIndex.HipCenter].SetTRS(Vector3.zero, quat, Vector3.one);
            }

            if (jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderLeft] && jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderRight])
            {
                // NUI_SKELETON_POSITION_SPINE
                if (jointsTracked[(int)NuiSkeletonPositionIndex.Spine] && jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderCenter])
                {
                    vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.Spine, NuiSkeletonPositionIndex.ShoulderCenter);
                    vx = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ShoulderLeft, NuiSkeletonPositionIndex.ShoulderRight);
                    MakeMatrixFromYX(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.Spine]);
                }

                if (jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderCenter] && jointsTracked[(int)NuiSkeletonPositionIndex.Head])
                {
                    // NUI_SKELETON_POSITION_SHOULDER_CENTER
                    //if(jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderCenter] && jointsTracked[(int)NuiSkeletonPositionIndex.Head])
                    //{
                    vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ShoulderCenter, NuiSkeletonPositionIndex.Head);
                    vx = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ShoulderLeft, NuiSkeletonPositionIndex.ShoulderRight);
                    MakeMatrixFromYX(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.ShoulderCenter]);
                    //}

                    // NUI_SKELETON_POSITION_HEAD
                    //if(jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderCenter] && jointsTracked[(int)NuiSkeletonPositionIndex.Head])
                    //{
                    //			        vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ShoulderCenter, NuiSkeletonPositionIndex.Head);
                    //			        vx = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ShoulderLeft, NuiSkeletonPositionIndex.ShoulderRight);
                    MakeMatrixFromYX(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.Head]);
                    //MakeMatrixFromY(vy, ref jointOrients[(int)NuiSkeletonPositionIndex.Head]);
                    //}
                }
            }

            if (jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderLeft] && jointsTracked[(int)NuiSkeletonPositionIndex.ElbowLeft] &&
                //jointsTracked[(int)NuiSkeletonPositionIndex.WristLeft])
                jointsTracked[(int)NuiSkeletonPositionIndex.Spine] && jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderCenter])
            {
                // NUI_SKELETON_POSITION_SHOULDER_LEFT
                //if(jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderLeft] && jointsTracked[(int)NuiSkeletonPositionIndex.ElbowLeft])
                {
                    vx = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ShoulderLeft, NuiSkeletonPositionIndex.ElbowLeft);
                    //vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ElbowLeft, NuiSkeletonPositionIndex.WristLeft);
                    vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.Spine, NuiSkeletonPositionIndex.ShoulderCenter);
                    MakeMatrixFromXY(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.ShoulderLeft]);
                }

                // NUI_SKELETON_POSITION_ELBOW_LEFT
                //if(jointsTracked[(int)NuiSkeletonPositionIndex.ElbowLeft] && jointsTracked[(int)NuiSkeletonPositionIndex.WristLeft])
                {
                    vx = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ElbowLeft, NuiSkeletonPositionIndex.WristLeft);
                    //vy = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ShoulderLeft, NuiSkeletonPositionIndex.ElbowLeft);
                    vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.Spine, NuiSkeletonPositionIndex.ShoulderCenter);
                    MakeMatrixFromXY(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.ElbowLeft]);
                }
            }

            if (jointsTracked[(int)NuiSkeletonPositionIndex.WristLeft] && jointsTracked[(int)NuiSkeletonPositionIndex.HandLeft] &&
             jointsTracked[(int)NuiSkeletonPositionIndex.Spine] && jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderCenter])
            {
                // NUI_SKELETON_POSITION_WRIST_LEFT
                //if(jointsTracked[(int)NuiSkeletonPositionIndex.WristLeft] && jointsTracked[(int)NuiSkeletonPositionIndex.HandLeft])
                //{
                vx = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.WristLeft, NuiSkeletonPositionIndex.HandLeft);
                //MakeMatrixFromX(vx, ref jointOrients[(int)NuiSkeletonPositionIndex.WristLeft], false);
                vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.Spine, NuiSkeletonPositionIndex.ShoulderCenter);
                MakeMatrixFromXY(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.WristLeft]);
                //}

                // NUI_SKELETON_POSITION_HAND_LEFT:
                //if(jointsTracked[(int)NuiSkeletonPositionIndex.WristLeft] && jointsTracked[(int)NuiSkeletonPositionIndex.HandLeft])
                //{
                //		        vx = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.WristLeft, NuiSkeletonPositionIndex.HandLeft);
                //		        //MakeMatrixFromX(vx, ref jointOrients[(int)NuiSkeletonPositionIndex.HandLeft], false);
                //				vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.Spine, NuiSkeletonPositionIndex.ShoulderCenter);
                MakeMatrixFromXY(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.HandLeft]);
                //}
            }

            if (jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderRight] && jointsTracked[(int)NuiSkeletonPositionIndex.ElbowRight] &&
                //jointsTracked[(int)NuiSkeletonPositionIndex.WristRight])
                jointsTracked[(int)NuiSkeletonPositionIndex.Spine] && jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderCenter])
            {
                // NUI_SKELETON_POSITION_SHOULDER_RIGHT
                //if(jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderRight] && jointsTracked[(int)NuiSkeletonPositionIndex.ElbowRight])
                {
                    vx = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ShoulderRight, NuiSkeletonPositionIndex.ElbowRight);
                    //vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ElbowRight, NuiSkeletonPositionIndex.WristRight);
                    vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.Spine, NuiSkeletonPositionIndex.ShoulderCenter);
                    MakeMatrixFromXY(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.ShoulderRight]);
                }

                // NUI_SKELETON_POSITION_ELBOW_RIGHT
                //if(jointsTracked[(int)NuiSkeletonPositionIndex.ElbowRight] && jointsTracked[(int)NuiSkeletonPositionIndex.WristRight])
                {
                    vx = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ElbowRight, NuiSkeletonPositionIndex.WristRight);
                    //vy = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.ShoulderRight, NuiSkeletonPositionIndex.ElbowRight);
                    vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.Spine, NuiSkeletonPositionIndex.ShoulderCenter);
                    MakeMatrixFromXY(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.ElbowRight]);
                }
            }

            if (jointsTracked[(int)NuiSkeletonPositionIndex.WristRight] && jointsTracked[(int)NuiSkeletonPositionIndex.HandRight] &&
                jointsTracked[(int)NuiSkeletonPositionIndex.Spine] && jointsTracked[(int)NuiSkeletonPositionIndex.ShoulderCenter])
            {
                // NUI_SKELETON_POSITION_WRIST_RIGHT
                //if(jointsTracked[(int)NuiSkeletonPositionIndex.WristRight] && jointsTracked[(int)NuiSkeletonPositionIndex.HandRight])
                //{
                vx = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.WristRight, NuiSkeletonPositionIndex.HandRight);
                //MakeMatrixFromX(vx, ref jointOrients[(int)NuiSkeletonPositionIndex.WristRight], true);
                vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.Spine, NuiSkeletonPositionIndex.ShoulderCenter);
                MakeMatrixFromXY(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.WristRight]);
                //}

                // NUI_SKELETON_POSITION_HAND_RIGHT
                //if(jointsTracked[(int)NuiSkeletonPositionIndex.WristRight] && jointsTracked[(int)NuiSkeletonPositionIndex.HandRight])
                //{
                //		        vx = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.WristRight, NuiSkeletonPositionIndex.HandRight);
                //		        //MakeMatrixFromX(vx, ref jointOrients[(int)NuiSkeletonPositionIndex.HandRight], true);
                //				vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.Spine, NuiSkeletonPositionIndex.ShoulderCenter);
                MakeMatrixFromXY(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.HandRight]);
                //}
            }

            // NUI_SKELETON_POSITION_HIP_LEFT
            if (jointsTracked[(int)NuiSkeletonPositionIndex.HipLeft] && jointsTracked[(int)NuiSkeletonPositionIndex.KneeLeft] &&
                jointsTracked[(int)NuiSkeletonPositionIndex.HipRight])
            {
                vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.KneeLeft, NuiSkeletonPositionIndex.HipLeft);
                vx = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.HipLeft, NuiSkeletonPositionIndex.HipRight);
                MakeMatrixFromYX(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.HipLeft]);

                // NUI_SKELETON_POSITION_KNEE_LEFT
                if (jointsTracked[(int)NuiSkeletonPositionIndex.AnkleLeft])
                {
                    vy = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.KneeLeft, NuiSkeletonPositionIndex.AnkleLeft);
                    //vz = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.AnkleLeft, NuiSkeletonPositionIndex.FootLeft);
                    //MakeMatrixFromYZ(vy, vz, ref jointOrients[(int)NuiSkeletonPositionIndex.KneeLeft]);
                    vx = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.HipLeft, NuiSkeletonPositionIndex.HipRight);
                    MakeMatrixFromYX(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.KneeLeft]);
                }
            }

            if (jointsTracked[(int)NuiSkeletonPositionIndex.KneeLeft] && jointsTracked[(int)NuiSkeletonPositionIndex.AnkleLeft] &&
                jointsTracked[(int)NuiSkeletonPositionIndex.FootLeft])
            {
                // NUI_SKELETON_POSITION_ANKLE_LEFT
                //if(jointsTracked[(int)NuiSkeletonPositionIndex.AnkleLeft] && jointsTracked[(int)NuiSkeletonPositionIndex.FootLeft])
                //{
                vy = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.KneeLeft, NuiSkeletonPositionIndex.AnkleLeft);
                vz = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.FootLeft, NuiSkeletonPositionIndex.AnkleLeft);
                MakeMatrixFromYZ(vy, vz, ref jointOrients[(int)NuiSkeletonPositionIndex.AnkleLeft]);
                //MakeMatrixFromZ(vz, ref jointOrients[(int)NuiSkeletonPositionIndex.AnkleLeft]);
                //}

                // NUI_SKELETON_POSITION_FOOT_LEFT
                //if(jointsTracked[(int)NuiSkeletonPositionIndex.AnkleLeft] && jointsTracked[(int)NuiSkeletonPositionIndex.FootLeft])
                //{
                //		        vy = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.KneeLeft, NuiSkeletonPositionIndex.AnkleLeft);
                //		        vz = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.FootLeft, NuiSkeletonPositionIndex.AnkleLeft);
                MakeMatrixFromYZ(vy, vz, ref jointOrients[(int)NuiSkeletonPositionIndex.FootLeft]);
                //MakeMatrixFromZ(vz, ref jointOrients[(int)NuiSkeletonPositionIndex.FootLeft]);
                //}
            }

            // NUI_SKELETON_POSITION_HIP_RIGHT
            if (jointsTracked[(int)NuiSkeletonPositionIndex.HipRight] && jointsTracked[(int)NuiSkeletonPositionIndex.KneeRight] &&
                jointsTracked[(int)NuiSkeletonPositionIndex.HipLeft])
            {
                vy = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.KneeRight, NuiSkeletonPositionIndex.HipRight);
                vx = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.HipLeft, NuiSkeletonPositionIndex.HipRight);
                MakeMatrixFromYX(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.HipRight]);

                // NUI_SKELETON_POSITION_KNEE_RIGHT
                if (jointsTracked[(int)NuiSkeletonPositionIndex.AnkleRight])
                {
                    vy = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.KneeRight, NuiSkeletonPositionIndex.AnkleRight);
                    //vz = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.AnkleRight, NuiSkeletonPositionIndex.FootRight);
                    //MakeMatrixFromYZ(vy, vz, ref jointOrients[(int)NuiSkeletonPositionIndex.KneeRight]);
                    vx = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.HipLeft, NuiSkeletonPositionIndex.HipRight);
                    MakeMatrixFromYX(vx, vy, ref jointOrients[(int)NuiSkeletonPositionIndex.KneeRight]);
                }
            }

            if (jointsTracked[(int)NuiSkeletonPositionIndex.KneeRight] && jointsTracked[(int)NuiSkeletonPositionIndex.AnkleRight] &&
                jointsTracked[(int)NuiSkeletonPositionIndex.FootRight])
            {
                // NUI_SKELETON_POSITION_ANKLE_RIGHT
                //if(jointsTracked[(int)NuiSkeletonPositionIndex.AnkleRight] && jointsTracked[(int)NuiSkeletonPositionIndex.FootRight])
                //{
                vy = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.KneeRight, NuiSkeletonPositionIndex.AnkleRight);
                vz = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.FootRight, NuiSkeletonPositionIndex.AnkleRight);
                MakeMatrixFromYZ(vy, vz, ref jointOrients[(int)NuiSkeletonPositionIndex.AnkleRight]);
                //MakeMatrixFromZ(vz, ref jointOrients[(int)NuiSkeletonPositionIndex.AnkleRight]);
                //}

                // NUI_SKELETON_POSITION_FOOT_RIGHT
                //if(jointsTracked[(int)NuiSkeletonPositionIndex.AnkleRight] && jointsTracked[(int)NuiSkeletonPositionIndex.FootRight])
                //{
                //		        vy = -GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.KneeRight, NuiSkeletonPositionIndex.AnkleRight);
                //		        vz = GetPositionBetweenIndices(ref jointsPos, NuiSkeletonPositionIndex.FootRight, NuiSkeletonPositionIndex.AnkleRight);
                MakeMatrixFromYZ(vy, vz, ref jointOrients[(int)NuiSkeletonPositionIndex.FootRight]);
                //MakeMatrixFromZ(vz, ref jointOrients[(int)NuiSkeletonPositionIndex.FootRight]);
                //}
            }
        }


    }
}