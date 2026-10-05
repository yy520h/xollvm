%Str = type { i64, i64, ptr }       ; std::string-ish: data @16
%Resp = type { i32, i32, %Str, i64 }  ; key_id (a %Str) @ offset 8, size 24
declare i32 @ext_ok(i32)
define internal ptr @c_str(ptr %s) {
entry:
  %p = getelementptr %Str, ptr %s, i64 0, i32 2
  %v = load ptr, ptr %p
  ret ptr %v
}
declare i32 @streq(ptr, ptr)
define i32 @check(ptr %resp, ptr %expect, i32 %x) {
entry:
  %r = call i32 @ext_ok(i32 %x)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %c, label %f0
c:
  %kid = getelementptr %Resp, ptr %resp, i64 0, i32 2
  %a = call ptr @c_str(ptr %kid)
  %s = call i32 @streq(ptr %a, ptr %expect)
  %ok2 = icmp eq i32 %s, 1
  br i1 %ok2, label %s2, label %f1
s2: ret i32 0
f0: ret i32 1
f1: ret i32 2
}
@.a = private unnamed_addr constant [104 x i8] c"\6F\62\66\3A\20\73\65\6E\73\69\74\69\76\65\28\72\65\67\69\6F\6E\3D\74\2C\73\74\72\69\63\74\3D\31\29\2C\20\76\6D\28\65\6E\63\42\79\74\65\63\6F\64\65\3D\30\2C\6C\61\7A\79\44\65\63\72\79\70\74\3D\30\2C\63\6F\6E\73\74\49\6E\53\74\72\65\61\6D\3D\30\2C\68\61\72\64\65\6E\65\64\3D\30\2C\72\61\6E\64\49\53\41\3D\30\29\00"
@llvm.global.annotations = appending global [1 x { ptr, ptr, ptr, i32, ptr }] [{ ptr, ptr, ptr, i32, ptr } { ptr @check, ptr @.a, ptr @.a, i32 0, ptr null }]
