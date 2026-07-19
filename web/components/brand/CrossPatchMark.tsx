import Image from "next/image";

type CrossPatchMarkProps = {
  className?: string;
  size?: number;
};

export function CrossPatchMark({ className, size = 48 }: CrossPatchMarkProps) {
  return (
    <Image
      aria-hidden="true"
      alt=""
      className={className}
      height={size}
      src="/crosspatch-mark.png"
      unoptimized
      width={size}
    />
  );
}
